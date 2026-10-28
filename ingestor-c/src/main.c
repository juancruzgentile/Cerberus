/**
 * @file main.c
 * @brief Cerberus Head 1 — CLI & Lightweight Loopback HTTP Server (127.0.0.1)
 *
 * Supports:
 *   1. CLI Single Event Mode:
 *      cerberus-ingestor --db <path> [--schema <path>] --ingest \
 *          --source <src> --level <lvl> --message <msg> \
 *          [--metadata <json>] [--webhook <url>]
 *   2. CLI Self-Test Mode:
 *      cerberus-ingestor --db <path> [--schema <path>] --self-test
 *   3. HTTP Server Mode (127.0.0.1:<port>):
 *      cerberus-ingestor --db <path> [--schema <path>] --serve <port>
 *      Endpoints:
 *        - GET  /health -> {"status":"ok","service":"cerberus-ingestor"}
 *        - POST /ingest -> {"status":"ok","event_id":123}
 */

#define _POSIX_C_SOURCE 200809L

#include "cerberus_ingestor.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_HTTP_REQ_SIZE 32768U
#define MAX_JSON_DEPTH    32
#define HTTP_WALL_TIMEOUT_MS 2000L
#define MAX_ACTIVE_CLIENTS   32      /* concurrent connections; extra ones get 503 */
#define MAX_CORS_ORIGINS     4
#define MAX_ORIGIN_LEN       256
#define SHUTDOWN_GRACE_MS    1500L   /* in-flight requests may finish normally */
#define SHUTDOWN_CANCEL_MS   3000L   /* after cerberus_interrupt(); then give up */
#define SERVE_WORKERS_STUCK  2       /* run_http_server(): workers still using the DB */

static volatile sig_atomic_t g_stop_server = 0;

/* Browser origins allowed to call POST /ingest (e.g. the Rust dashboard). */
static const char *g_cors_origins[MAX_CORS_ORIGINS];
static size_t g_cors_count = 0;

/* Serializes use of the shared cerberus_db_t (its prepared statements are
 * not safe to bind/step from two threads at once). */
static pthread_mutex_t g_db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Active worker counter (bounded concurrency + clean shutdown). */
static pthread_mutex_t g_active_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_active_cond = PTHREAD_COND_INITIALIZER;
static int g_active_clients = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_stop_server = 1;
}

/* ============================================================================
 * Strict JSON (RFC 8259) parser for POST /ingest
 *
 * The WHOLE document is validated (including fields we ignore), raw strings
 * must be well-formed UTF-8 and \uXXXX escapes (with surrogate pairs) are
 * decoded to UTF-8. Anything else is rejected with 400.
 * ============================================================================ */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        ++p;
    }
    return p;
}

static int hex4(const char *p, unsigned int *out) {
    unsigned int v = 0;
    for (int i = 0; i < 4; ++i) {
        char h = p[i];
        v <<= 4;
        if (h >= '0' && h <= '9') v |= (unsigned int)(h - '0');
        else if (h >= 'a' && h <= 'f') v |= (unsigned int)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') v |= (unsigned int)(h - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

static size_t utf8_encode(unsigned int cp, char out[4]) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/**
 * Parses a JSON string literal starting right after the opening '"'.
 * If `out` is non-NULL the decoded UTF-8 text is written there (NUL-terminated;
 * U+0000 is rejected because it would truncate the C string).
 * Returns the pointer after the closing '"', or NULL if invalid / too long.
 */
static const char *parse_json_string(const char *p, char *out, size_t out_cap) {
    size_t idx = 0;
    for (;;) {
        unsigned char c = (unsigned char)*p;
        char tmp[4];
        size_t n = 1;
        if (c == '\0' || c < 0x20) {
            return NULL; /* unterminated or raw control character */
        }
        if (c == '"') {
            if (out) {
                out[idx] = '\0';
            }
            return p + 1;
        }
        if (c == '\\') {
            char esc = p[1];
            p += 2;
            switch (esc) {
                case '"':  tmp[0] = '"';  break;
                case '\\': tmp[0] = '\\'; break;
                case '/':  tmp[0] = '/';  break;
                case 'b':  tmp[0] = '\b'; break;
                case 'f':  tmp[0] = '\f'; break;
                case 'n':  tmp[0] = '\n'; break;
                case 'r':  tmp[0] = '\r'; break;
                case 't':  tmp[0] = '\t'; break;
                case 'u': {
                    unsigned int cp;
                    if (!hex4(p, &cp)) return NULL;
                    p += 4;
                    if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return NULL; /* lone low surrogate */
                    }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        unsigned int lo;
                        if (p[0] != '\\' || p[1] != 'u' || !hex4(p + 2, &lo) ||
                            lo < 0xDC00 || lo > 0xDFFF) {
                            return NULL; /* high surrogate without its pair */
                        }
                        p += 6;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    if (cp == 0 && out) {
                        return NULL;
                    }
                    n = utf8_encode(cp, tmp);
                    break;
                }
                default:
                    return NULL;
            }
        } else if (c >= 0x80) {
            n = cerberus_utf8_seq_len((const unsigned char *)p, strnlen(p, 4));
            if (n == 0) {
                return NULL; /* invalid UTF-8 */
            }
            memcpy(tmp, p, n);
            p += n;
        } else {
            tmp[0] = (char)c;
            ++p;
        }
        if (out) {
            if (idx + n + 1 > out_cap) {
                return NULL;
            }
            memcpy(out + idx, tmp, n);
        }
        idx += n;
    }
}

static const char *parse_json_number(const char *p) {
    if (*p == '-') ++p;
    if (*p == '0') {
        ++p;
    } else if (*p >= '1' && *p <= '9') {
        while (isdigit((unsigned char)*p)) ++p;
    } else {
        return NULL;
    }
    if (*p == '.') {
        ++p;
        if (!isdigit((unsigned char)*p)) return NULL;
        while (isdigit((unsigned char)*p)) ++p;
    }
    if (*p == 'e' || *p == 'E') {
        ++p;
        if (*p == '+' || *p == '-') ++p;
        if (!isdigit((unsigned char)*p)) return NULL;
        while (isdigit((unsigned char)*p)) ++p;
    }
    return p;
}

/** Validates (and skips) any JSON value. Returns pointer after it, or NULL. */
static const char *skip_json_value(const char *p, int depth) {
    p = skip_ws(p);
    if (depth > MAX_JSON_DEPTH) {
        return NULL;
    }
    switch (*p) {
        case '"':
            return parse_json_string(p + 1, NULL, 0);
        case 't':
            return strncmp(p, "true", 4) == 0 ? p + 4 : NULL;
        case 'f':
            return strncmp(p, "false", 5) == 0 ? p + 5 : NULL;
        case 'n':
            return strncmp(p, "null", 4) == 0 ? p + 4 : NULL;
        case '[': {
            p = skip_ws(p + 1);
            if (*p == ']') return p + 1;
            for (;;) {
                p = skip_json_value(p, depth + 1);
                if (!p) return NULL;
                p = skip_ws(p);
                if (*p == ']') return p + 1;
                if (*p != ',') return NULL;
                ++p;
            }
        }
        case '{': {
            p = skip_ws(p + 1);
            if (*p == '}') return p + 1;
            for (;;) {
                if (*p != '"') return NULL;
                p = parse_json_string(p + 1, NULL, 0);
                if (!p) return NULL;
                p = skip_ws(p);
                if (*p != ':') return NULL;
                p = skip_json_value(p + 1, depth + 1);
                if (!p) return NULL;
                p = skip_ws(p);
                if (*p == '}') return p + 1;
                if (*p != ',') return NULL;
                p = skip_ws(p + 1);
            }
        }
        default:
            return parse_json_number(p);
    }
}

/** True if `s` is exactly one JSON object (surrounding whitespace allowed). */
static bool is_json_object(const char *s) {
    s = skip_ws(s);
    if (*s != '{') return false;
    s = skip_json_value(s, 1);
    return s && *skip_ws(s) == '\0';
}

typedef struct {
    char source[CERBERUS_MAX_SOURCE_LEN + 2];
    char level[CERBERUS_MAX_LEVEL_LEN + 2];
    char message[CERBERUS_MAX_MESSAGE_LEN + 2];
    char metadata_json[CERBERUS_MAX_METADATA_LEN + 2];
    char webhook_url[CERBERUS_MAX_WEBHOOK_URL_LEN + 2];
    bool has_source;
    bool has_level;
    bool has_message;
    bool has_metadata;
    bool has_webhook;
} parsed_payload_t;

/* Parses a required string field; rejects duplicates of the same key. */
static const char *parse_string_field(const char *p, char *out, size_t cap, bool *seen) {
    if (*seen || *p != '"') return NULL;
    *seen = true;
    return parse_json_string(p + 1, out, cap);
}

static bool parse_ingest_json_body(const char *body, parsed_payload_t *out) {
    memset(out, 0, sizeof(*out));
    bool seen_webhook = false, seen_metadata = false;
    const char *p = skip_ws(body);
    if (*p != '{') {
        return false;
    }
    p = skip_ws(p + 1);
    if (*p == '}') {
        return *skip_ws(p + 1) == '\0';
    }

    for (;;) {
        if (*p != '"') return false;
        char key[64];
        p = parse_json_string(p + 1, key, sizeof(key));
        if (!p) {
            /* Invalid string or key longer than 63 bytes */
            return false;
        }
        p = skip_ws(p);
        if (*p != ':') return false;
        p = skip_ws(p + 1);

        if (strcmp(key, "source") == 0) {
            p = parse_string_field(p, out->source, sizeof(out->source), &out->has_source);
        } else if (strcmp(key, "level") == 0) {
            p = parse_string_field(p, out->level, sizeof(out->level), &out->has_level);
        } else if (strcmp(key, "message") == 0) {
            p = parse_string_field(p, out->message, sizeof(out->message), &out->has_message);
        } else if (strcmp(key, "webhook_url") == 0) {
            if (seen_webhook) return false;
            seen_webhook = true;
            if (strncmp(p, "null", 4) == 0) {
                p += 4;
            } else if (*p == '"') {
                p = parse_json_string(p + 1, out->webhook_url, sizeof(out->webhook_url));
                out->has_webhook = p && out->webhook_url[0] != '\0';
            } else {
                return false;
            }
        } else if (strcmp(key, "metadata_json") == 0 || strcmp(key, "metadata") == 0) {
            if (seen_metadata) return false;
            seen_metadata = true;
            if (strncmp(p, "null", 4) == 0) {
                p += 4;
            } else if (*p == '"') {
                /* Metadata sent as a string must itself contain a JSON object */
                p = parse_json_string(p + 1, out->metadata_json, sizeof(out->metadata_json));
                if (!p || !is_json_object(out->metadata_json)) return false;
                out->has_metadata = true;
            } else if (*p == '{') {
                const char *start = p;
                p = skip_json_value(p, 2);
                if (!p) return false;
                size_t len = (size_t)(p - start);
                if (len >= sizeof(out->metadata_json)) return false;
                memcpy(out->metadata_json, start, len);
                out->metadata_json[len] = '\0';
                out->has_metadata = true;
            } else {
                return false;
            }
        } else {
            /* Unknown field: ignored, but it must still be valid JSON */
            p = skip_json_value(p, 2);
        }
        if (!p) return false;

        p = skip_ws(p);
        if (*p == '}') {
            return *skip_ws(p + 1) == '\0';
        }
        if (*p != ',') return false;
        p = skip_ws(p + 1);
    }
}

/* ============================================================================
 * HTTP Server (127.0.0.1:<port>)
 * ============================================================================ */

static void send_http_json_ex(int client_fd, int status_code, const char *status_text,
                              const char *json_body, const char *extra_headers) {
    char header[1024];
    size_t body_len = strlen(json_body);
    int hlen = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        status_text,
        body_len,
        extra_headers ? extra_headers : ""
    );
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    if (hlen > 0 && (size_t)hlen < sizeof(header)) {
        (void)send(client_fd, header, (size_t)hlen, flags);
        (void)send(client_fd, json_body, body_len, flags);
    }
}

static void send_http_json(int client_fd, int status_code, const char *status_text, const char *json_body) {
    send_http_json_ex(client_fd, status_code, status_text, json_body, NULL);
}

/* Origin = scheme://host[:port], no path, no whitespace/control chars. */
static bool is_valid_origin(const char *o) {
    size_t len = strlen(o);
    const char *host;
    if (strncmp(o, "http://", 7) == 0) host = o + 7;
    else if (strncmp(o, "https://", 8) == 0) host = o + 8;
    else return false;
    if (len >= MAX_ORIGIN_LEN || *host == '\0') return false;
    for (const char *c = host; *c; ++c) {
        if ((unsigned char)*c <= 0x20 || *c == 0x7F || *c == '/' || *c == '@' || *c == '\\') return false;
    }
    return true;
}

static bool origin_allowed(const char *origin) {
    for (size_t i = 0; i < g_cors_count; ++i) {
        if (strcmp(origin, g_cors_origins[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Copies a header value (trimmed) into out; returns false if too long. */
static bool copy_header_value(const char *v, const char *line_end, char *out, size_t cap) {
    while (v < line_end && (*v == ' ' || *v == '\t')) ++v;
    const char *e = line_end;
    while (e > v && (e[-1] == ' ' || e[-1] == '\t')) --e;
    size_t len = (size_t)(e - v);
    if (len >= cap) return false;
    memcpy(out, v, len);
    out[len] = '\0';
    return true;
}

static long elapsed_ms_since(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static void drain_socket_briefly(int client_fd) {
    char discard[4096];
    int flags = 0;
#ifdef MSG_DONTWAIT
    flags = MSG_DONTWAIT;
#endif
    for (int i = 0; i < 64; ++i) {
        ssize_t n = recv(client_fd, discard, sizeof(discard), flags);
        if (n <= 0) {
            break;
        }
    }
}

/**
 * Strictly parses a non-negative Content-Length header value.
 * Returns -1 on syntax error, -2 if value > MAX_HTTP_REQ_SIZE.
 */
static int parse_content_length_value(const char *val_start, const char *line_end, size_t *out_len) {
    const char *p = val_start;
    while (p < line_end && (*p == ' ' || *p == '\t')) {
        ++p;
    }
    if (p >= line_end || !isdigit((unsigned char)*p)) {
        return -1;
    }
    size_t acc = 0;
    bool overflow = false;
    while (p < line_end && isdigit((unsigned char)*p)) {
        size_t d = (size_t)(*p - '0');
        if (acc > (MAX_HTTP_REQ_SIZE * 4U) || acc * 10U + d > MAX_HTTP_REQ_SIZE) {
            overflow = true;
        } else {
            acc = acc * 10U + d;
        }
        ++p;
    }
    while (p < line_end && (*p == ' ' || *p == '\t')) {
        ++p;
    }
    if (p != line_end) {
        return -1;
    }
    if (overflow) {
        return -2;
    }
    *out_len = acc;
    return 0;
}

static void handle_http_client(int client_fd, cerberus_db_t *db) {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct timespec start_ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);

    char *buf = (char *)malloc(MAX_HTTP_REQ_SIZE + 1);
    if (!buf) {
        send_http_json(client_fd, 500, "Internal Server Error", "{\"status\":\"error\",\"error\":\"out of memory\"}\n");
        return;
    }

    size_t total_read = 0;
    char *header_end = NULL;
    size_t content_length = 0;
    bool has_content_length = false;
    bool payload_too_large = false;
    bool header_invalid = false;
    bool content_type_json = false;
    char origin[MAX_ORIGIN_LEN] = "";

    while (total_read < MAX_HTTP_REQ_SIZE) {
        if (elapsed_ms_since(&start_ts) >= HTTP_WALL_TIMEOUT_MS) {
            break;
        }
        ssize_t n = recv(client_fd, buf + total_read, MAX_HTTP_REQ_SIZE - total_read, 0);
        if (n <= 0) {
            break;
        }
        total_read += (size_t)n;
        buf[total_read] = '\0';

        if (!header_end) {
            header_end = strstr(buf, "\r\n\r\n");
            if (header_end) {
                /* Inspect headers for Content-Length and disallow Transfer-Encoding */
                const char *p = buf;
                while (p < header_end) {
                    const char *line_end = strstr(p, "\r\n");
                    if (!line_end || line_end > header_end) {
                        break;
                    }
                    size_t line_len = (size_t)(line_end - p);
                    if (line_len >= 15) {
                        char prefix[19];
                        size_t plen = (line_len < 18) ? line_len : 18;
                        for (size_t i = 0; i < plen; ++i) {
                            prefix[i] = (char)tolower((unsigned char)p[i]);
                        }
                        prefix[plen] = '\0';
                        if (strncmp(prefix, "content-length:", 15) == 0) {
                            if (has_content_length) {
                                /* Duplicate Content-Length header (request smuggling defense) */
                                header_invalid = true;
                                break;
                            }
                            has_content_length = true;
                            int cl_rc = parse_content_length_value(p + 15, line_end, &content_length);
                            if (cl_rc == -1) {
                                header_invalid = true;
                                break;
                            }
                            if (cl_rc == -2) {
                                payload_too_large = true;
                                break;
                            }
                        } else if (plen >= 18 && strncmp(prefix, "transfer-encoding:", 18) == 0) {
                            header_invalid = true;
                            break;
                        }
                    }
                    if (line_len >= 7 && strncasecmp(p, "origin:", 7) == 0) {
                        if (origin[0] != '\0' ||
                            !copy_header_value(p + 7, line_end, origin, sizeof(origin))) {
                            header_invalid = true;
                            break;
                        }
                    } else if (line_len >= 13 && strncasecmp(p, "content-type:", 13) == 0) {
                        char ct[128];
                        if (copy_header_value(p + 13, line_end, ct, sizeof(ct))) {
                            /* "application/json" optionally followed by parameters */
                            content_type_json = strncasecmp(ct, "application/json", 16) == 0 &&
                                                (ct[16] == '\0' || ct[16] == ';' || ct[16] == ' ');
                        }
                    }
                    p = line_end + 2;
                }
                if (header_invalid || payload_too_large) {
                    break;
                }
                size_t header_bytes = (size_t)((header_end + 4) - buf);
                if (header_bytes + content_length > MAX_HTTP_REQ_SIZE) {
                    payload_too_large = true;
                    break;
                }
            }
        }

        if (header_end) {
            size_t body_received = total_read - (size_t)((header_end + 4) - buf);
            if (body_received >= content_length) {
                break;
            }
        }
    }

    if (payload_too_large || (!header_end && total_read >= MAX_HTTP_REQ_SIZE)) {
        drain_socket_briefly(client_fd);
        send_http_json(client_fd, 413, "Payload Too Large", "{\"status\":\"error\",\"error\":\"payload exceeds 32KB limit\"}\n");
        drain_socket_briefly(client_fd);
        free(buf);
        return;
    }

    if (!header_end || header_invalid) {
        send_http_json(client_fd, 400, "Bad Request", "{\"status\":\"error\",\"error\":\"malformed HTTP request\"}\n");
        free(buf);
        return;
    }

    size_t header_bytes = (size_t)((header_end + 4) - buf);
    size_t body_received = total_read - header_bytes;
    if (body_received < content_length) {
        send_http_json(client_fd, 400, "Bad Request", "{\"status\":\"error\",\"error\":\"truncated HTTP body\"}\n");
        free(buf);
        return;
    }
    if (has_content_length) {
        buf[header_bytes + content_length] = '\0';
    }

    if (strncmp(buf, "GET /health ", 12) == 0 || strncmp(buf, "GET /health?", 12) == 0) {
        send_http_json(client_fd, 200, "OK", "{\"status\":\"ok\",\"service\":\"cerberus-ingestor\"}\n");
        free(buf);
        return;
    }

    bool is_ingest_path = strncmp(buf, "POST /ingest ", 13) == 0 || strncmp(buf, "POST /ingest?", 13) == 0;
    bool is_preflight = strncmp(buf, "OPTIONS /ingest ", 16) == 0 || strncmp(buf, "OPTIONS /ingest?", 16) == 0;

    /* CORS: only explicitly configured origins (--cors-origin) get headers.
     * A request carrying any other Origin is a cross-site browser call and is
     * rejected, so random web pages cannot write into the local ingestor. */
    char cors_hdr[MAX_ORIGIN_LEN + 128] = "";
    bool has_origin = origin[0] != '\0';
    bool cors_ok = has_origin && origin_allowed(origin);
    if (cors_ok) {
        snprintf(cors_hdr, sizeof(cors_hdr), "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\n", origin);
    }

    if (is_preflight) {
        if (!cors_ok) {
            send_http_json(client_fd, 403, "Forbidden", "{\"status\":\"error\",\"error\":\"origin not allowed\"}\n");
        } else {
            char hdrs[MAX_ORIGIN_LEN + 256];
            snprintf(hdrs, sizeof(hdrs),
                     "%sAccess-Control-Allow-Methods: POST, OPTIONS\r\n"
                     "Access-Control-Allow-Headers: Content-Type\r\n"
                     "Access-Control-Max-Age: 600\r\n", cors_hdr);
            send_http_json_ex(client_fd, 204, "No Content", "", hdrs);
        }
        free(buf);
        return;
    }

    if (is_ingest_path) {
        const char *body = header_end + 4;
        if (has_origin && !cors_ok) {
            send_http_json(client_fd, 403, "Forbidden", "{\"status\":\"error\",\"error\":\"origin not allowed\"}\n");
            free(buf);
            return;
        }
        if (!has_content_length) {
            send_http_json_ex(client_fd, 411, "Length Required",
                              "{\"status\":\"error\",\"error\":\"Content-Length required\"}\n", cors_hdr);
            free(buf);
            return;
        }
        if (!content_type_json) {
            send_http_json_ex(client_fd, 415, "Unsupported Media Type",
                              "{\"status\":\"error\",\"error\":\"Content-Type must be application/json\"}\n", cors_hdr);
            free(buf);
            return;
        }
        if (strlen(body) != content_length) {
            /* Embedded NUL byte: would silently truncate the document */
            send_http_json_ex(client_fd, 400, "Bad Request",
                              "{\"status\":\"error\",\"error\":\"body contains NUL bytes\"}\n", cors_hdr);
            free(buf);
            return;
        }
        parsed_payload_t *parsed = (parsed_payload_t *)calloc(1, sizeof(parsed_payload_t));
        if (!parsed) {
            send_http_json(client_fd, 500, "Internal Server Error", "{\"status\":\"error\",\"error\":\"out of memory\"}\n");
            free(buf);
            return;
        }

        if (!parse_ingest_json_body(body, parsed) ||
            !parsed->has_source || !parsed->has_level || !parsed->has_message) {
            send_http_json_ex(
                client_fd,
                400,
                "Bad Request",
                "{\"status\":\"error\",\"error\":\"invalid JSON payload or missing required fields (source, level, message)\"}\n",
                cors_hdr
            );
            free(parsed);
            free(buf);
            return;
        }

        cerberus_event_t ev = {
            .source = parsed->source,
            .level = parsed->level,
            .message = parsed->message,
            .metadata_json = parsed->has_metadata ? parsed->metadata_json : "{}",
            .webhook_url = parsed->has_webhook ? parsed->webhook_url : NULL
        };

        int64_t event_id = -1;
        pthread_mutex_lock(&g_db_mutex);
        cerberus_status_t st = cerberus_ingest_event(db, &ev, &event_id);
        pthread_mutex_unlock(&g_db_mutex);
        if (st == CERBERUS_OK) {
            char resp[128];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"event_id\":%" PRId64 "}\n", event_id);
            send_http_json_ex(client_fd, 201, "Created", resp, cors_hdr);
        } else {
            char resp[256];
            snprintf(
                resp,
                sizeof(resp),
                "{\"status\":\"error\",\"code\":%d,\"error\":\"%s\"}\n",
                (int)st,
                cerberus_status_str(st)
            );
            int http_code = (st >= CERBERUS_ERR_NULL_PTR && st <= CERBERUS_ERR_INVALID_WEBHOOK) ||
                            st == CERBERUS_ERR_DB_CONSTRAINT
                                ? 400
                                : (st == CERBERUS_ERR_CANCELLED ? 503 : 500);
            const char *http_txt = (http_code == 400)   ? "Bad Request"
                                   : (http_code == 503) ? "Service Unavailable"
                                                        : "Internal Server Error";
            send_http_json_ex(client_fd, http_code, http_txt, resp, cors_hdr);
        }

        free(parsed);
        free(buf);
        return;
    }

    send_http_json(client_fd, 404, "Not Found", "{\"status\":\"error\",\"error\":\"endpoint not found\"}\n");
    free(buf);
}

typedef struct {
    int fd;
    cerberus_db_t *db;
} client_job_t;

static void worker_done(void) {
    pthread_mutex_lock(&g_active_mutex);
    g_active_clients--;
    pthread_cond_broadcast(&g_active_cond);
    pthread_mutex_unlock(&g_active_mutex);
}

static void *client_worker(void *arg) {
    client_job_t *job = (client_job_t *)arg;
    handle_http_client(job->fd, job->db);
    close(job->fd);
    free(job);
    worker_done();
    return NULL;
}

/* Waits up to `ms` for every worker to finish; returns how many are left. */
static int wait_for_workers(long ms) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += ms / 1000;
    deadline.tv_nsec += (ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_active_mutex);
    while (g_active_clients > 0) {
        if (pthread_cond_timedwait(&g_active_cond, &g_active_mutex, &deadline) != 0) {
            break;
        }
    }
    int remaining = g_active_clients;
    pthread_mutex_unlock(&g_active_mutex);
    return remaining;
}

static int run_http_server(cerberus_db_t *db, uint16_t port) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    (void)setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* Strictly 127.0.0.1 */

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 64) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    fprintf(stdout, "{\"status\":\"listening\",\"bind\":\"127.0.0.1:%u\"}\n", (unsigned)port);
    fflush(stdout);

    /* Signals must interrupt only the accept loop, never a worker. */
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);

    while (!g_stop_server) {
        /* poll() with timeout so SIGTERM is honoured within 250 ms */
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 250);
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR) {
                perror("poll");
                break;
            }
            continue;
        }
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN) {
                continue;
            }
            perror("accept");
            break;
        }

        pthread_mutex_lock(&g_active_mutex);
        bool busy = g_active_clients >= MAX_ACTIVE_CLIENTS;
        if (!busy) {
            g_active_clients++;
        }
        pthread_mutex_unlock(&g_active_mutex);
        if (busy) {
            send_http_json(client_fd, 503, "Service Unavailable", "{\"status\":\"error\",\"error\":\"server busy\"}\n");
            close(client_fd);
            continue;
        }

        client_job_t *job = (client_job_t *)malloc(sizeof(*job));
        pthread_t tid;
        bool started = false;
        if (job) {
            job->fd = client_fd;
            job->db = db;
            pthread_sigmask(SIG_BLOCK, &block_set, &old_set);
            started = pthread_create(&tid, NULL, client_worker, job) == 0;
            pthread_sigmask(SIG_SETMASK, &old_set, NULL);
            if (started) {
                pthread_detach(tid);
            }
        }
        if (!started) {
            free(job);
            send_http_json(client_fd, 503, "Service Unavailable", "{\"status\":\"error\",\"error\":\"server busy\"}\n");
            close(client_fd);
            worker_done();
        }
    }

    /* 1. Stop taking new requests. */
    close(server_fd);

    /* 2. Grace period: let in-flight requests finish normally. */
    int remaining = wait_for_workers(SHUTDOWN_GRACE_MS);
    if (remaining > 0) {
        /* 3. Cancel what is left: running statements are interrupted, waits on
         *    a locked database end now and queued requests get 503. */
        fprintf(stderr, "{\"status\":\"shutdown\",\"cancelling_workers\":%d}\n", remaining);
        cerberus_interrupt(db);
        remaining = wait_for_workers(SHUTDOWN_CANCEL_MS);
    }
    /* 4. Only the caller closes SQLite, and only when this returns 0. */
    return remaining > 0 ? SERVE_WORKERS_STUCK : 0;
}

/* ============================================================================
 * Built-in Self-Test Suite
 * ============================================================================ */

static int run_self_test(cerberus_db_t *db) {
    /* 1. Valid INFO event */
    cerberus_event_t ev1 = {
        .source = "firewall-edge-01",
        .level = "INFO",
        .message = "Accepted TLS 1.3 handshake from internal gateway",
        .metadata_json = "{\"src_ip\":\"10.0.0.12\",\"cipher\":\"TLS_AES_256_GCM_SHA384\"}",
        .webhook_url = NULL
    };
    int64_t id1 = -1;
    cerberus_status_t st = cerberus_ingest_event(db, &ev1, &id1);
    if (st != CERBERUS_OK || id1 <= 0) {
        fprintf(stderr, "[FAIL] Test 1 (valid INFO): %s (%s)\n", cerberus_status_str(st), cerberus_last_error(db));
        return 1;
    }

    /* 2. Valid CRITICAL event with webhook_url (atomic event + alert_deliveries) */
    cerberus_event_t ev2 = {
        .source = "ids-suricata-core",
        .level = "CRITICAL",
        .message = "Possible RCE payload detected on /api/v1/auth",
        .metadata_json = "{\"rule_id\":90042,\"attacker_ip\":\"198.51.100.77\"}",
        .webhook_url = "https://127.0.0.1:8443/alerts/webhook"
    };
    int64_t id2 = -1;
    st = cerberus_ingest_event(db, &ev2, &id2);
    if (st != CERBERUS_OK || id2 <= id1) {
        fprintf(stderr, "[FAIL] Test 2 (valid CRITICAL + webhook): %s\n", cerberus_status_str(st));
        return 1;
    }

    /* 3. SSRF protection: block cloud metadata IP 169.254.169.254 */
    cerberus_event_t ev_ssrf = {
        .source = "auth-service",
        .level = "ERROR",
        .message = "SSRF attempt test",
        .metadata_json = "{}",
        .webhook_url = "http://169.254.169.254/latest/meta-data/"
    };
    st = cerberus_ingest_event(db, &ev_ssrf, NULL);
    if (st != CERBERUS_ERR_INVALID_WEBHOOK) {
        fprintf(stderr, "[FAIL] Test 3 (SSRF metadata block): expected INVALID_WEBHOOK, got %s\n", cerberus_status_str(st));
        return 1;
    }

    /* 4. CRLF injection in webhook_url must be blocked */
    cerberus_event_t ev_crlf = {
        .source = "auth-service",
        .level = "ERROR",
        .message = "CRLF attempt test",
        .metadata_json = "{}",
        .webhook_url = "http://example.com/hook\r\nX-Injected: true"
    };
    st = cerberus_ingest_event(db, &ev_crlf, NULL);
    if (st != CERBERUS_ERR_INVALID_WEBHOOK) {
        fprintf(stderr, "[FAIL] Test 4 (CRLF webhook block): expected INVALID_WEBHOOK, got %s\n", cerberus_status_str(st));
        return 1;
    }

    /* 5. Invalid level must be blocked */
    cerberus_event_t ev_lvl = {
        .source = "auth-service",
        .level = "FATAL",
        .message = "Invalid level test",
        .metadata_json = "{}",
        .webhook_url = NULL
    };
    st = cerberus_ingest_event(db, &ev_lvl, NULL);
    if (st != CERBERUS_ERR_INVALID_LEVEL) {
        fprintf(stderr, "[FAIL] Test 5 (invalid level): expected INVALID_LEVEL, got %s\n", cerberus_status_str(st));
        return 1;
    }

    /* 6. Batch ingestion (atomic BEGIN IMMEDIATE / COMMIT) */
    cerberus_event_t batch[3] = {
        {
            .source = "k8s-audit",
            .level = "DEBUG",
            .message = "Pod scheduled on worker-02",
            .metadata_json = "{\"pod\":\"api-6d4f\"}",
            .webhook_url = NULL
        },
        {
            .source = "k8s-audit",
            .level = "WARN",
            .message = "High memory pressure on worker-02",
            .metadata_json = "{\"mem_pct\":89}",
            .webhook_url = NULL
        },
        {
            .source = "k8s-audit",
            .level = "ERROR",
            .message = "OOMKilled container in namespace prod",
            .metadata_json = "{\"container\":\"worker\"}",
            .webhook_url = "http://127.0.0.1:9090/webhook"
        }
    };
    size_t inserted = 0;
    st = cerberus_ingest_batch(db, batch, 3, &inserted);
    if (st != CERBERUS_OK || inserted != 3) {
        fprintf(stderr, "[FAIL] Test 6 (batch ingest): %s (%s)\n", cerberus_status_str(st), cerberus_last_error(db));
        return 1;
    }

    fprintf(stdout, "{\"status\":\"ok\",\"self_test\":\"passed\",\"events_inserted\":5}\n");
    return 0;
}

/* ============================================================================
 * CLI Entry Point
 * ============================================================================ */

static void print_usage(const char *prog) {
    fprintf(
        stderr,
        "Usage:\n"
        "  %s --db <path> [--schema <path>] --ingest --source <src> --level <lvl> --message <msg> [--metadata <json>] [--webhook <url>]\n"
        "  %s --db <path> [--schema <path>] --serve <port> [--cors-origin <origin>]...\n"
        "  %s --db <path> [--schema <path>] --self-test\n",
        prog, prog, prog
    );
}

int main(int argc, char **argv) {
    const char *db_path = NULL;
    const char *schema_path = NULL;
    const char *source = NULL;
    const char *level = NULL;
    const char *message = NULL;
    const char *metadata = "{}";
    const char *webhook = NULL;

    bool mode_ingest = false;
    bool mode_self_test = false;
    bool mode_serve = false;
    uint16_t serve_port = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--schema") == 0 && i + 1 < argc) {
            schema_path = argv[++i];
        } else if (strcmp(argv[i], "--ingest") == 0) {
            mode_ingest = true;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            mode_self_test = true;
        } else if (strcmp(argv[i], "--serve") == 0 && i + 1 < argc) {
            mode_serve = true;
            unsigned long p = strtoul(argv[++i], NULL, 10);
            if (p == 0 || p > 65535UL) {
                fprintf(stderr, "Error: invalid port number\n");
                return 1;
            }
            serve_port = (uint16_t)p;
        } else if (strcmp(argv[i], "--cors-origin") == 0 && i + 1 < argc) {
            const char *o = argv[++i];
            if (g_cors_count >= MAX_CORS_ORIGINS || !is_valid_origin(o)) {
                fprintf(stderr, "Error: invalid --cors-origin\n");
                return 1;
            }
            g_cors_origins[g_cors_count++] = o;
        } else if (strcmp(argv[i], "--source") == 0 && i + 1 < argc) {
            source = argv[++i];
        } else if (strcmp(argv[i], "--level") == 0 && i + 1 < argc) {
            level = argv[++i];
        } else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
            message = argv[++i];
        } else if (strcmp(argv[i], "--metadata") == 0 && i + 1 < argc) {
            metadata = argv[++i];
        } else if (strcmp(argv[i], "--webhook") == 0 && i + 1 < argc) {
            webhook = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!db_path || (!mode_ingest && !mode_self_test && !mode_serve)) {
        print_usage(argv[0]);
        return 1;
    }

    cerberus_db_t *db = NULL;
    cerberus_status_t st = cerberus_init(db_path, schema_path, &db);
    if (st != CERBERUS_OK) {
        fprintf(stderr, "{\"status\":\"error\",\"code\":%d,\"error\":\"%s\"}\n", (int)st, cerberus_status_str(st));
        return 1;
    }

    int exit_code = 0;

    if (mode_self_test) {
        exit_code = run_self_test(db);
    } else if (mode_ingest) {
        cerberus_event_t ev = {
            .source = source,
            .level = level,
            .message = message,
            .metadata_json = metadata,
            .webhook_url = webhook
        };
        int64_t event_id = -1;
        st = cerberus_ingest_event(db, &ev, &event_id);
        if (st == CERBERUS_OK) {
            fprintf(stdout, "{\"status\":\"ok\",\"event_id\":%" PRId64 "}\n", event_id);
        } else {
            fprintf(
                stderr,
                "{\"status\":\"error\",\"code\":%d,\"error\":\"%s\",\"detail\":\"%s\"}\n",
                (int)st,
                cerberus_status_str(st),
                cerberus_last_error(db)
            );
            exit_code = 1;
        }
    } else if (mode_serve) {
        exit_code = run_http_server(db, serve_port);
        if (exit_code == SERVE_WORKERS_STUCK) {
            /* Bounded exit: a worker may still be inside SQLite, so the handle
             * is NOT closed (that would be a use-after-free). The process ends
             * now; WAL keeps the database consistent. */
            fprintf(stderr, "{\"status\":\"error\",\"error\":\"workers did not stop; exiting without closing the database\"}\n");
            fflush(NULL);
            _exit(1);
        }
    }

    cerberus_close(db);
    return exit_code;
}
