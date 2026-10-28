/**
 * @file ingestor.c
 * @brief Implementation of the Cerberus C11 Ingestor Core Library
 */

#define _POSIX_C_SOURCE 200809L

#include "cerberus_ingestor.h"
#include "sqlite3.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ============================================================================
 * Internal Structures & Embedded Fallback Schema
 * ============================================================================ */

struct cerberus_db {
    sqlite3 *conn;
    sqlite3_stmt *insert_event_stmt;
    sqlite3_stmt *insert_alert_stmt;
    sqlite3_stmt *begin_imm_stmt;
    sqlite3_stmt *commit_stmt;
    sqlite3_stmt *rollback_stmt;
    char last_error[512];
};

static const char *EMBEDDED_PRAGMAS_AND_SCHEMA =
    "PRAGMA journal_mode = WAL;\n"
    "PRAGMA synchronous = NORMAL;\n"
    "PRAGMA foreign_keys = ON;\n"
    "PRAGMA busy_timeout = 5000;\n"
    "CREATE TABLE IF NOT EXISTS events (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    source TEXT NOT NULL CHECK(length(source) > 0 AND length(source) <= 128),\n"
    "    level TEXT NOT NULL CHECK(level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')),\n"
    "    message TEXT NOT NULL CHECK(length(message) > 0 AND length(message) <= 8192),\n"
    "    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json) AND json_type(metadata_json) = 'object' AND length(metadata_json) <= 16384),\n"
    "    created_at INTEGER NOT NULL DEFAULT (unixepoch())\n"
    ");\n"
    "CREATE TABLE IF NOT EXISTS alert_deliveries (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,\n"
    "    target_url TEXT NOT NULL CHECK(\n"
    "        length(target_url) >= 10\n"
    "        AND length(target_url) <= 1024\n"
    "        AND (target_url GLOB 'http://?*' OR target_url GLOB 'https://?*')\n"
    "        AND instr(target_url, ' ') = 0\n"
    "        AND instr(target_url, char(9)) = 0\n"
    "        AND instr(target_url, char(10)) = 0\n"
    "        AND instr(target_url, char(13)) = 0\n"
    "        AND instr(lower(target_url), '169.254.169.254') = 0\n"
    "        AND instr(lower(target_url), 'metadata.google.internal') = 0\n"
    "        AND instr(lower(target_url), '0.0.0.0') = 0\n"
    "    ),\n"
    "    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'SENT', 'FAILED', 'DEAD')),\n"
    "    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),\n"
    "    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts >= 1 AND max_attempts <= 10),\n"
    "    next_retry_at INTEGER NOT NULL DEFAULT (unixepoch()),\n"
    "    last_error TEXT NOT NULL DEFAULT '' CHECK(length(last_error) <= 2048),\n"
    "    updated_at INTEGER NOT NULL DEFAULT (unixepoch())\n"
    ");\n"
    "CREATE INDEX IF NOT EXISTS idx_events_level_created ON events(level, created_at DESC);\n"
    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source, created_at DESC);\n"
    "CREATE INDEX IF NOT EXISTS idx_alerts_status_retry ON alert_deliveries(status, next_retry_at ASC);\n"
    "CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(\n"
    "    source, level, message, metadata_json, content='events', content_rowid='id'\n"
    ");\n"
    "CREATE TRIGGER IF NOT EXISTS trg_events_ai AFTER INSERT ON events BEGIN\n"
    "    INSERT INTO events_fts(rowid, source, level, message, metadata_json)\n"
    "    VALUES (new.id, new.source, new.level, new.message, new.metadata_json);\n"
    "END;\n"
    "CREATE TRIGGER IF NOT EXISTS trg_events_ad AFTER DELETE ON events BEGIN\n"
    "    INSERT INTO events_fts(events_fts, rowid, source, level, message, metadata_json)\n"
    "    VALUES ('delete', old.id, old.source, old.level, old.message, old.metadata_json);\n"
    "END;\n"
    "CREATE TRIGGER IF NOT EXISTS trg_events_au AFTER UPDATE ON events BEGIN\n"
    "    INSERT INTO events_fts(events_fts, rowid, source, level, message, metadata_json)\n"
    "    VALUES ('delete', old.id, old.source, old.level, old.message, old.metadata_json);\n"
    "    INSERT INTO events_fts(rowid, source, level, message, metadata_json)\n"
    "    VALUES (new.id, new.source, new.level, new.message, new.metadata_json);\n"
    "END;\n";

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static void set_db_error(cerberus_db_t *db, const char *msg) {
    if (!db) {
        return;
    }
    if (msg) {
        snprintf(db->last_error, sizeof(db->last_error), "%s", msg);
    } else if (db->conn) {
        snprintf(db->last_error, sizeof(db->last_error), "%s", sqlite3_errmsg(db->conn));
    } else {
        db->last_error[0] = '\0';
    }
}

const char *cerberus_status_str(cerberus_status_t status) {
    switch (status) {
        case CERBERUS_OK:               return "OK";
        case CERBERUS_ERR_NULL_PTR:     return "Null pointer argument";
        case CERBERUS_ERR_INVALID_SOURCE:   return "Invalid source (must be 1..128 bytes of valid UTF-8)";
        case CERBERUS_ERR_INVALID_LEVEL:    return "Invalid level (must be DEBUG, INFO, WARN, ERROR, or CRITICAL)";
        case CERBERUS_ERR_INVALID_MESSAGE:  return "Invalid message (must be 1..8192 bytes of valid UTF-8)";
        case CERBERUS_ERR_INVALID_METADATA: return "Invalid metadata_json (must be a UTF-8 JSON object <= 16384 bytes)";
        case CERBERUS_ERR_INVALID_WEBHOOK:  return "Invalid or unsafe webhook_url";
        case CERBERUS_ERR_IO:           return "File I/O or permission error";
        case CERBERUS_ERR_DB_OPEN:      return "Failed to open SQLite database";
        case CERBERUS_ERR_DB_SCHEMA:    return "Failed to apply SQLite schema or PRAGMAs";
        case CERBERUS_ERR_DB_PREPARE:   return "Failed to prepare SQLite statement";
        case CERBERUS_ERR_DB_EXEC:      return "Failed to execute SQLite statement";
        case CERBERUS_ERR_DB_CONSTRAINT:return "Database constraint violation";
        case CERBERUS_ERR_NOMEM:        return "Out of memory";
        default:                        return "Unknown error";
    }
}

const char *cerberus_last_error(const cerberus_db_t *db) {
    if (!db) {
        return "NULL database handle";
    }
    return db->last_error;
}

size_t cerberus_utf8_seq_len(const unsigned char *p, size_t avail) {
    if (avail == 0) {
        return 0;
    }
    unsigned char c = p[0];
    if (c < 0x80) {
        return 1;
    }
    size_t n;
    unsigned char lo = 0x80, hi = 0xBF; /* allowed range for the 2nd byte */
    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        if (c == 0xE0) lo = 0xA0;      /* no overlongs */
        if (c == 0xED) hi = 0x9F;      /* no UTF-16 surrogates */
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        if (c == 0xF0) lo = 0x90;      /* no overlongs */
        if (c == 0xF4) hi = 0x8F;      /* <= U+10FFFF */
    } else {
        return 0;
    }
    if (avail < n || p[1] < lo || p[1] > hi) {
        return 0;
    }
    for (size_t i = 2; i < n; ++i) {
        if ((p[i] & 0xC0) != 0x80) {
            return 0;
        }
    }
    return n;
}

int cerberus_utf8_valid(const char *s, size_t len) {
    const unsigned char *p = (const unsigned char *)s;
    size_t i = 0;
    while (i < len) {
        size_t n = cerberus_utf8_seq_len(p + i, len - i);
        if (n == 0) {
            return 0;
        }
        i += n;
    }
    return 1;
}

static bool is_valid_level(const char *level, bool *out_is_alertable) {
    if (!level) {
        return false;
    }
    if (strcmp(level, "DEBUG") == 0 || strcmp(level, "INFO") == 0 || strcmp(level, "WARN") == 0) {
        if (out_is_alertable) {
            *out_is_alertable = false;
        }
        return true;
    }
    if (strcmp(level, "ERROR") == 0 || strcmp(level, "CRITICAL") == 0) {
        if (out_is_alertable) {
            *out_is_alertable = true;
        }
        return true;
    }
    return false;
}

/**
 * Case-insensitive substring search in C11 without non-standard strcasestr.
 */
static bool contains_case_insensitive(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0) {
        return true;
    }
    for (const char *p = haystack; *p != '\0'; ++p) {
        size_t i = 0;
        while (i < needle_len && p[i] != '\0' &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            ++i;
        }
        if (i == needle_len) {
            return true;
        }
    }
    return false;
}

/**
 * Defensive C-level validation for webhook URLs:
 * - Length between 10 and 1024 bytes
 * - Must start with http:// or https:// followed by a valid host
 * - No spaces, tabs, CR, LF, backslashes, userinfo '@', or control characters
 * - Blocks cloud metadata endpoints (169.254.0.0/16, metadata.google.internal,
 *   metadata.goog, [fd00:ec2::254], 100.100.100.200), wildcard bind addresses
 *   (0.0.0.0, [::], [::0]), and integer/hex/octal IP obfuscations.
 */
static bool is_valid_webhook_url(const char *url) {
    if (!url) {
        return false;
    }
    size_t len = strnlen(url, CERBERUS_MAX_WEBHOOK_URL_LEN + 1);
    if (len < CERBERUS_MIN_WEBHOOK_URL_LEN || len > CERBERUS_MAX_WEBHOOK_URL_LEN) {
        return false;
    }

    const char *host_start = NULL;
    if (strncmp(url, "http://", 7) == 0) {
        host_start = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        host_start = url + 8;
    } else {
        return false;
    }

    if (*host_start == '\0' || *host_start == '/' || *host_start == ':' ||
        *host_start == '?' || *host_start == '#' || *host_start == '@') {
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)url[i];
        if (c <= 0x20 || c == 0x7F || c == '\\') {
            /* Rejects space (0x20), \t, \n, \r, backslash, and control chars */
            return false;
        }
    }
    if (!cerberus_utf8_valid(url, len)) {
        return false;
    }

    /* Extract authority and host portion to prevent SSRF bypasses */
    const char *auth_end = host_start;
    while (*auth_end != '\0' && *auth_end != '/' && *auth_end != '?' && *auth_end != '#') {
        if (*auth_end == '@') {
            /* Disallow userinfo credentials (e.g. http://safe@169.254.169.254/) */
            return false;
        }
        auth_end++;
    }

    const char *host_end = host_start;
    if (*host_start == '[') {
        /* IPv6 literal in brackets */
        const char *close_bracket = strchr(host_start, ']');
        if (!close_bracket || close_bracket >= auth_end) {
            return false;
        }
        host_end = close_bracket + 1;
    } else {
        while (host_end < auth_end && *host_end != ':') {
            host_end++;
        }
    }

    size_t host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len > 255) {
        return false;
    }

    char host[256];
    for (size_t i = 0; i < host_len; ++i) {
        host[i] = (char)tolower((unsigned char)host_start[i]);
    }
    host[host_len] = '\0';

    /* Block 0.0.0.0/8, IPv6 unspecified [::], and raw integer/hex/octal IP encodings */
    if (strcmp(host, "0.0.0.0") == 0 ||
        strcmp(host, "0") == 0 ||
        strncmp(host, "0.", 2) == 0 ||
        strcmp(host, "[::]") == 0 ||
        strcmp(host, "[::0]") == 0 ||
        strcmp(host, "[0:0:0:0:0:0:0:0]") == 0 ||
        strncmp(host, "0x", 2) == 0 ||
        strncmp(host, "0251.", 5) == 0) {
        return false;
    }

    /* Reject purely numeric decimal IP (e.g. http://2852039166/ for 169.254.169.254) */
    bool all_digits = true;
    for (size_t i = 0; i < host_len; ++i) {
        if (!isdigit((unsigned char)host[i])) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        return false;
    }

    if (contains_case_insensitive(url, "169.254.") ||
        contains_case_insensitive(url, "metadata.google.internal") ||
        contains_case_insensitive(url, "metadata.goog") ||
        contains_case_insensitive(url, "fd00:ec2::254") ||
        contains_case_insensitive(url, "100.100.100.200") ||
        contains_case_insensitive(url, "0.0.0.0")) {
        return false;
    }

    return true;
}

/**
 * Basic structural check that metadata_json starts with '{' and ends with '}'
 * (ignoring leading/trailing ASCII whitespace) before SQLite's json_valid()
 * and json_type() = 'object' enforce full RFC 8259 syntax.
 */
static bool is_plausible_json_object(const char *json, size_t len) {
    size_t start = 0;
    while (start < len && isspace((unsigned char)json[start])) {
        start++;
    }
    if (start >= len || json[start] != '{') {
        return false;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)json[end - 1])) {
        end--;
    }
    if (end <= start || json[end - 1] != '}') {
        return false;
    }
    return true;
}

cerberus_status_t cerberus_validate_event(const cerberus_event_t *event) {
    if (!event) {
        return CERBERUS_ERR_NULL_PTR;
    }
    if (!event->source) {
        return CERBERUS_ERR_INVALID_SOURCE;
    }
    size_t source_len = strnlen(event->source, CERBERUS_MAX_SOURCE_LEN + 1);
    if (source_len == 0 || source_len > CERBERUS_MAX_SOURCE_LEN) {
        return CERBERUS_ERR_INVALID_SOURCE;
    }
    for (size_t i = 0; i < source_len; ++i) {
        unsigned char c = (unsigned char)event->source[i];
        if (c < 0x20 || c == 0x7F) {
            return CERBERUS_ERR_INVALID_SOURCE;
        }
    }
    if (!cerberus_utf8_valid(event->source, source_len)) {
        return CERBERUS_ERR_INVALID_SOURCE;
    }

    if (!event->level) {
        return CERBERUS_ERR_INVALID_LEVEL;
    }
    bool is_alertable = false;
    if (!is_valid_level(event->level, &is_alertable)) {
        return CERBERUS_ERR_INVALID_LEVEL;
    }

    if (!event->message) {
        return CERBERUS_ERR_INVALID_MESSAGE;
    }
    size_t msg_len = strnlen(event->message, CERBERUS_MAX_MESSAGE_LEN + 1);
    if (msg_len == 0 || msg_len > CERBERUS_MAX_MESSAGE_LEN ||
        !cerberus_utf8_valid(event->message, msg_len)) {
        return CERBERUS_ERR_INVALID_MESSAGE;
    }

    if (event->metadata_json != NULL) {
        size_t meta_len = strnlen(event->metadata_json, CERBERUS_MAX_METADATA_LEN + 1);
        if (meta_len == 0 || meta_len > CERBERUS_MAX_METADATA_LEN ||
            !cerberus_utf8_valid(event->metadata_json, meta_len) ||
            !is_plausible_json_object(event->metadata_json, meta_len)) {
            return CERBERUS_ERR_INVALID_METADATA;
        }
    }

    if (event->webhook_url != NULL && event->webhook_url[0] != '\0') {
        if (!is_valid_webhook_url(event->webhook_url)) {
            return CERBERUS_ERR_INVALID_WEBHOOK;
        }
    }

    return CERBERUS_OK;
}

static char *read_file_contents(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > (1024L * 1024L)) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);
    if (read_bytes != (size_t)fsize) {
        free(buf);
        return NULL;
    }
    buf[fsize] = '\0';
    return buf;
}

static cerberus_status_t exec_simple_stmt(cerberus_db_t *db, sqlite3_stmt *stmt) {
    sqlite3_reset(stmt);
    int rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        set_db_error(db, NULL);
        return CERBERUS_ERR_DB_EXEC;
    }
    return CERBERUS_OK;
}

/* ============================================================================
 * Database Lifecycle
 * ============================================================================ */

cerberus_status_t cerberus_init(const char *db_path, const char *schema_path, cerberus_db_t **out_db) {
    if (!db_path || !out_db || db_path[0] == '\0') {
        return CERBERUS_ERR_NULL_PTR;
    }
    *out_db = NULL;

    /* Pre-create or enforce 0600 permissions if not an in-memory database */
    bool is_memory = (strcmp(db_path, ":memory:") == 0 || strncmp(db_path, "file::memory:", 13) == 0);
    if (!is_memory) {
        int fd = open(db_path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            return CERBERUS_ERR_IO;
        }
        if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
            close(fd);
            return CERBERUS_ERR_IO;
        }
        close(fd);
    }

    cerberus_db_t *db = (cerberus_db_t *)calloc(1, sizeof(cerberus_db_t));
    if (!db) {
        return CERBERUS_ERR_NOMEM;
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int rc = sqlite3_open_v2(db_path, &db->conn, flags, NULL);
    if (rc != SQLITE_OK || !db->conn) {
        cerberus_close(db);
        return CERBERUS_ERR_DB_OPEN;
    }

    /* Enforce mandatory PRAGMAs immediately */
    const char *mandatory_pragmas =
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"
        "PRAGMA foreign_keys = ON;"
        "PRAGMA busy_timeout = 5000;";
    char *errmsg = NULL;
    rc = sqlite3_exec(db->conn, mandatory_pragmas, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) {
            sqlite3_free(errmsg);
        }
        cerberus_close(db);
        return CERBERUS_ERR_DB_SCHEMA;
    }

    /* Load schema SQL from schema_path if provided, else use embedded schema */
    char *schema_sql = NULL;
    if (schema_path && schema_path[0] != '\0') {
        schema_sql = read_file_contents(schema_path);
        if (!schema_sql) {
            cerberus_close(db);
            return CERBERUS_ERR_IO;
        }
    }

    const char *sql_to_apply = schema_sql ? schema_sql : EMBEDDED_PRAGMAS_AND_SCHEMA;
    rc = sqlite3_exec(db->conn, sql_to_apply, NULL, NULL, &errmsg);
    free(schema_sql);
    if (rc != SQLITE_OK) {
        if (errmsg) {
            sqlite3_free(errmsg);
        }
        cerberus_close(db);
        return CERBERUS_ERR_DB_SCHEMA;
    }

    /* Ensure 0600 on WAL/SHM files if created */
    if (!is_memory) {
        (void)chmod(db_path, S_IRUSR | S_IWUSR);
        const char *suffixes[] = { "-wal", "-shm" };
        for (size_t i = 0; i < 2; ++i) {
            char aux[4096];
            int n = snprintf(aux, sizeof(aux), "%s%s", db_path, suffixes[i]);
            if (n > 0 && (size_t)n < sizeof(aux)) {
                (void)chmod(aux, S_IRUSR | S_IWUSR); /* ENOENT is fine */
            }
        }
    }

    /* Precompile Prepared Statements */
    const char *sql_insert_event =
        "INSERT INTO events (source, level, message, metadata_json) VALUES (?1, ?2, ?3, ?4);";
    const char *sql_insert_alert =
        "INSERT INTO alert_deliveries (event_id, target_url, status, attempts, max_attempts) "
        "VALUES (?1, ?2, 'PENDING', 0, ?3);";

    if (sqlite3_prepare_v2(db->conn, sql_insert_event, -1, &db->insert_event_stmt, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, sql_insert_alert, -1, &db->insert_alert_stmt, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, "BEGIN IMMEDIATE;", -1, &db->begin_imm_stmt, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, "COMMIT;", -1, &db->commit_stmt, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, "ROLLBACK;", -1, &db->rollback_stmt, NULL) != SQLITE_OK) {
        cerberus_close(db);
        return CERBERUS_ERR_DB_PREPARE;
    }

    *out_db = db;
    return CERBERUS_OK;
}

void cerberus_close(cerberus_db_t *db) {
    if (!db) {
        return;
    }
    if (db->insert_event_stmt) {
        sqlite3_finalize(db->insert_event_stmt);
    }
    if (db->insert_alert_stmt) {
        sqlite3_finalize(db->insert_alert_stmt);
    }
    if (db->begin_imm_stmt) {
        sqlite3_finalize(db->begin_imm_stmt);
    }
    if (db->commit_stmt) {
        sqlite3_finalize(db->commit_stmt);
    }
    if (db->rollback_stmt) {
        sqlite3_finalize(db->rollback_stmt);
    }
    if (db->conn) {
        sqlite3_close_v2(db->conn);
    }
    free(db);
}

/* ============================================================================
 * Event & Batch Ingestion
 * ============================================================================ */

/**
 * Internal helper that executes the prepared statement insertion for one
 * already-validated event. Assumes caller manages transactions if needed.
 */
static cerberus_status_t insert_single_event_no_tx(
    cerberus_db_t *db,
    const cerberus_event_t *event,
    int64_t *out_event_id
) {
    const char *meta = (event->metadata_json && event->metadata_json[0] != '\0')
                           ? event->metadata_json
                           : "{}";

    sqlite3_reset(db->insert_event_stmt);
    sqlite3_clear_bindings(db->insert_event_stmt);

    if (sqlite3_bind_text(db->insert_event_stmt, 1, event->source, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(db->insert_event_stmt, 2, event->level, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(db->insert_event_stmt, 3, event->message, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(db->insert_event_stmt, 4, meta, -1, SQLITE_STATIC) != SQLITE_OK) {
        set_db_error(db, NULL);
        sqlite3_reset(db->insert_event_stmt);
        sqlite3_clear_bindings(db->insert_event_stmt);
        return CERBERUS_ERR_DB_EXEC;
    }

    int rc = sqlite3_step(db->insert_event_stmt);
    sqlite3_reset(db->insert_event_stmt);
    sqlite3_clear_bindings(db->insert_event_stmt);

    if (rc != SQLITE_DONE) {
        set_db_error(db, NULL);
        if (rc == SQLITE_CONSTRAINT) {
            return CERBERUS_ERR_DB_CONSTRAINT;
        }
        return CERBERUS_ERR_DB_EXEC;
    }

    int64_t event_id = (int64_t)sqlite3_last_insert_rowid(db->conn);

    bool is_alertable = false;
    (void)is_valid_level(event->level, &is_alertable);

    if (is_alertable && event->webhook_url != NULL && event->webhook_url[0] != '\0') {
        sqlite3_reset(db->insert_alert_stmt);
        sqlite3_clear_bindings(db->insert_alert_stmt);

        if (sqlite3_bind_int64(db->insert_alert_stmt, 1, (sqlite3_int64)event_id) != SQLITE_OK ||
            sqlite3_bind_text(db->insert_alert_stmt, 2, event->webhook_url, -1, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int(db->insert_alert_stmt, 3, CERBERUS_DEFAULT_MAX_ATTEMPTS) != SQLITE_OK) {
            set_db_error(db, NULL);
            sqlite3_reset(db->insert_alert_stmt);
            sqlite3_clear_bindings(db->insert_alert_stmt);
            return CERBERUS_ERR_DB_EXEC;
        }

        rc = sqlite3_step(db->insert_alert_stmt);
        sqlite3_reset(db->insert_alert_stmt);
        sqlite3_clear_bindings(db->insert_alert_stmt);

        if (rc != SQLITE_DONE) {
            set_db_error(db, NULL);
            if (rc == SQLITE_CONSTRAINT) {
                return CERBERUS_ERR_DB_CONSTRAINT;
            }
            return CERBERUS_ERR_DB_EXEC;
        }
    }

    if (out_event_id) {
        *out_event_id = event_id;
    }
    return CERBERUS_OK;
}

cerberus_status_t cerberus_ingest_event(cerberus_db_t *db, const cerberus_event_t *event, int64_t *out_event_id) {
    if (!db || !db->conn || !event) {
        return CERBERUS_ERR_NULL_PTR;
    }
    if (out_event_id) {
        *out_event_id = -1;
    }

    cerberus_status_t vstatus = cerberus_validate_event(event);
    if (vstatus != CERBERUS_OK) {
        set_db_error(db, cerberus_status_str(vstatus));
        return vstatus;
    }

    bool is_alertable = false;
    (void)is_valid_level(event->level, &is_alertable);
    bool needs_tx = is_alertable && (event->webhook_url != NULL && event->webhook_url[0] != '\0');

    if (needs_tx) {
        cerberus_status_t tx_status = exec_simple_stmt(db, db->begin_imm_stmt);
        if (tx_status != CERBERUS_OK) {
            return tx_status;
        }
    }

    int64_t event_id = -1;
    cerberus_status_t status = insert_single_event_no_tx(db, event, &event_id);
    if (status != CERBERUS_OK) {
        if (needs_tx) {
            (void)exec_simple_stmt(db, db->rollback_stmt);
        }
        return status;
    }

    if (needs_tx) {
        cerberus_status_t commit_status = exec_simple_stmt(db, db->commit_stmt);
        if (commit_status != CERBERUS_OK) {
            (void)exec_simple_stmt(db, db->rollback_stmt);
            return commit_status;
        }
    }

    if (out_event_id) {
        *out_event_id = event_id;
    }
    return CERBERUS_OK;
}

cerberus_status_t cerberus_ingest_batch(
    cerberus_db_t *db,
    const cerberus_event_t *events,
    size_t count,
    size_t *out_inserted
) {
    if (out_inserted) {
        *out_inserted = 0;
    }
    if (!db || !db->conn || (!events && count > 0)) {
        return CERBERUS_ERR_NULL_PTR;
    }
    if (count == 0) {
        return CERBERUS_OK;
    }
    if (count > CERBERUS_MAX_BATCH_SIZE || count > (SIZE_MAX / sizeof(cerberus_event_t))) {
        set_db_error(db, "Batch count exceeds maximum allowed limit");
        return CERBERUS_ERR_NOMEM;
    }

    /* Pre-validate entire batch defensively in C before touching SQLite */
    for (size_t i = 0; i < count; ++i) {
        cerberus_status_t vstatus = cerberus_validate_event(&events[i]);
        if (vstatus != CERBERUS_OK) {
            set_db_error(db, cerberus_status_str(vstatus));
            return vstatus;
        }
    }

    cerberus_status_t tx_status = exec_simple_stmt(db, db->begin_imm_stmt);
    if (tx_status != CERBERUS_OK) {
        return tx_status;
    }

    for (size_t i = 0; i < count; ++i) {
        cerberus_status_t st = insert_single_event_no_tx(db, &events[i], NULL);
        if (st != CERBERUS_OK) {
            (void)exec_simple_stmt(db, db->rollback_stmt);
            return st;
        }
    }

    cerberus_status_t commit_status = exec_simple_stmt(db, db->commit_stmt);
    if (commit_status != CERBERUS_OK) {
        (void)exec_simple_stmt(db, db->rollback_stmt);
        return commit_status;
    }

    if (out_inserted) {
        *out_inserted = count;
    }
    return CERBERUS_OK;
}
