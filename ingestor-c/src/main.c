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
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_HTTP_REQ_SIZE 32768U
#define MAX_JSON_DEPTH    32
#define HTTP_WALL_TIMEOUT_MS 2000L

static volatile sig_atomic_t g_stop_server = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_stop_server = 1;
}

/* ============================================================================
 * Minimal Safe JSON Payload Extractor for POST /ingest
 * ============================================================================ */

static const char *skip_ws(const char *p) {
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

/**
 * Unescapes a JSON string literal (starting right after opening '"') into `out`.
 * Returns pointer after closing '"', or NULL on malformed string or buffer overflow.
 */
static const char *parse_json_string(const char *p, char *out, size_t out_cap) {
    size_t idx = 0;
    while (*p != '\0') {
        char c = *p++;
        if (c == '"') {
            if (idx >= out_cap) {
                return NULL;
            }
            out[idx] = '\0';
            return p;
        }
        /* RFC 8259: unescaped control characters (U+0000..U+001F) are invalid */
        if ((unsigned char)c < 0x20) {
            return NULL;
        }
        if (c == '\\') {
            char esc = *p++;
            if (esc == '\0') {
                return NULL;
            }
            switch (esc) {
                case '"':  c = '"'; break;
                case '\\': c = '\\'; break;
                case '/':  c = '/'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                case 'n':  c = '\n'; break;
                case 'r':  c = '\r'; break;
                case 't':  c = '\t'; break;
                case 'u': {
                    /* Parse 4 hex digits; reject null byte \u0000 injection */
                    unsigned int code = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = p[i];
                        if (!isxdigit((unsigned char)h)) {
                            return NULL;
                        }
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= (unsigned int)(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= (unsigned int)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= (unsigned int)(h - 'A' + 10);
                    }
                    if (code == 0) {
                        return NULL;
                    }
                    p += 4;
                    c = (code < 0x80) ? (char)code : '?';
                    break;
                }
                default:
                    return NULL;
            }
        }
        if (idx + 1 >= out_cap) {
            return NULL;
        }
        out[idx++] = c;
    }
    return NULL;
}

/**
 * Extracts a balanced JSON object `{ ... }` into `out_buf`.
 */
static const char *extract_json_object(const char *p, char *out_buf, size_t out_cap) {
    if (*p != '{') {
        return NULL;
    }
    const char *start = p;
    int depth = 0;
    bool in_str = false;

    while (*p != '\0') {
        char c = *p++;
        if (in_str) {
            if ((unsigned char)c < 0x20) {
                return NULL;
            }
            if (c == '\\') {
                if (*p == '\0') {
                    return NULL;
                }
                ++p;
            } else if (c == '"') {
                in_str = false;
            }
        } else {
            if (c == '"') {
                in_str = true;
            } else if (c == '{') {
                depth++;
                if (depth > MAX_JSON_DEPTH) {
                    return NULL;
                }
            } else if (c == '}') {
                depth--;
                if (depth < 0) {
                    return NULL;
                }
                if (depth == 0) {
                    size_t len = (size_t)(p - start);
                    if (len == 0 || len >= out_cap) {
                        return NULL;
                    }
                    memcpy(out_buf, start, len);
                    out_buf[len] = '\0';
                    return p;
                }
            }
        }
    }
    return NULL;
}

/**
 * Skips any JSON value (primitive, array, or object).
 */
static const char *skip_json_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') {
        ++p;
        while (*p != '\0') {
            if ((unsigned char)*p < 0x20) {
                return NULL;
            }
            if (*p == '\\') {
                if (p[1] == '\0') {
                    return NULL;
                }
                p += 2;
            } else if (*p == '"') {
                return p + 1;
            } else {
                ++p;
            }
        }
        return NULL;
    }
    if (*p == '{' || *p == '[') {
        char open_ch = *p;
        char close_ch = (open_ch == '{') ? '}' : ']';
        int depth = 0;
        bool in_str = false;
        while (*p != '\0') {
            char c = *p++;
            if (in_str) {
                if ((unsigned char)c < 0x20) {
                    return NULL;
                }
                if (c == '\\') {
                    if (*p == '\0') {
                        return NULL;
                    }
                    ++p;
                } else if (c == '"') {
                    in_str = false;
                }
            } else {
                if (c == '"') {
                    in_str = true;
                } else if (c == open_ch) {
                    depth++;
                    if (depth > MAX_JSON_DEPTH) {
                        return NULL;
                    }
                } else if (c == close_ch) {
                    depth--;
                    if (depth == 0) {
                        return p;
                    }
                }
            }
        }
        return NULL;
    }
    while (*p != '\0' && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
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

static bool parse_ingest_json_body(const char *body, parsed_payload_t *out) {
    memset(out, 0, sizeof(*out));
    const char *p = skip_ws(body);
    if (*p != '{') {
        return false;
    }
    ++p;

    while (*p != '\0') {
        p = skip_ws(p);
        if (*p == '}') {
            ++p;
            p = skip_ws(p);
            return (*p == '\0');
        }
        if (*p != '"') {
            return false;
        }
        ++p;
        char key[64];
        p = parse_json_string(p, key, sizeof(key));
        if (!p) {
            return false;
        }
        p = skip_ws(p);
        if (*p != ':') {
            return false;
        }
        ++p;
        p = skip_ws(p);

        if (strcmp(key, "source") == 0) {
            if (*p != '"') return false;
            p = parse_json_string(p + 1, out->source, sizeof(out->source));
            if (!p) return false;
            out->has_source = true;
        } else if (strcmp(key, "level") == 0) {
            if (*p != '"') return false;
            p = parse_json_string(p + 1, out->level, sizeof(out->level));
            if (!p) return false;
            out->has_level = true;
        } else if (strcmp(key, "message") == 0) {
            if (*p != '"') return false;
            p = parse_json_string(p + 1, out->message, sizeof(out->message));
            if (!p) return false;
            out->has_message = true;
        } else if (strcmp(key, "webhook_url") == 0) {
            if (strncmp(p, "null", 4) == 0) {
                p += 4;
                out->has_webhook = false;
            } else if (*p == '"') {
                p = parse_json_string(p + 1, out->webhook_url, sizeof(out->webhook_url));
                if (!p) return false;
                out->has_webhook = (out->webhook_url[0] != '\0');
            } else {
                return false;
            }
        } else if (strcmp(key, "metadata_json") == 0 || strcmp(key, "metadata") == 0) {
            if (strncmp(p, "null", 4) == 0) {
                p += 4;
                out->has_metadata = false;
            } else if (*p == '"') {
                p = parse_json_string(p + 1, out->metadata_json, sizeof(out->metadata_json));
                if (!p) return false;
                out->has_metadata = true;
            } else if (*p == '{') {
                p = extract_json_object(p, out->metadata_json, sizeof(out->metadata_json));
                if (!p) return false;
                out->has_metadata = true;
            } else {
                return false;
            }
        } else {
            p = skip_json_value(p);
            if (!p) return false;
        }

        p = skip_ws(p);
        if (*p == ',') {
            ++p;
            /* Disallow trailing comma before '}' */
            const char *next = skip_ws(p);
            if (*next == '}') {
                return false;
            }
        } else if (*p != '}') {
            return false;
        }
    }
    return false;
}

/* ============================================================================
 * HTTP Server (127.0.0.1:<port>)
 * ============================================================================ */

static void send_http_json(int client_fd, int status_code, const char *status_text, const char *json_body) {
    char header[512];
    size_t body_len = strlen(json_body);
    int hlen = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        status_text,
        body_len
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

    if (strncmp(buf, "POST /ingest ", 13) == 0 || strncmp(buf, "POST /ingest?", 13) == 0) {
        const char *body = header_end + 4;
        parsed_payload_t *parsed = (parsed_payload_t *)calloc(1, sizeof(parsed_payload_t));
        if (!parsed) {
            send_http_json(client_fd, 500, "Internal Server Error", "{\"status\":\"error\",\"error\":\"out of memory\"}\n");
            free(buf);
            return;
        }

        if (!parse_ingest_json_body(body, parsed) ||
            !parsed->has_source || !parsed->has_level || !parsed->has_message) {
            send_http_json(
                client_fd,
                400,
                "Bad Request",
                "{\"status\":\"error\",\"error\":\"invalid JSON payload or missing required fields (source, level, message)\"}\n"
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
        cerberus_status_t st = cerberus_ingest_event(db, &ev, &event_id);
        if (st == CERBERUS_OK) {
            char resp[128];
            snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"event_id\":%" PRId64 "}\n", event_id);
            send_http_json(client_fd, 201, "Created", resp);
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
                                : 500;
            const char *http_txt = (http_code == 400) ? "Bad Request" : "Internal Server Error";
            send_http_json(client_fd, http_code, http_txt, resp);
        }

        free(parsed);
        free(buf);
        return;
    }

    send_http_json(client_fd, 404, "Not Found", "{\"status\":\"error\",\"error\":\"endpoint not found\"}\n");
    free(buf);
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

    while (!g_stop_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        handle_http_client(client_fd, db);
        close(client_fd);
    }

    close(server_fd);
    return 0;
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
        "  %s --db <path> [--schema <path>] --serve <port>\n"
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
    }

    cerberus_close(db);
    return exit_code;
}
