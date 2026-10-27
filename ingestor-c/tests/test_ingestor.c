/**
 * @file test_ingestor.c
 * @brief Exhaustive C11 Unit & Integration Test Suite for Cerberus Head 1 (Ingestor)
 *
 * Covers:
 *   1. Database initialization (`cerberus_init`) & strict `0600` file permissions.
 *   2. Ingestion of valid events across all 5 severity levels (DEBUG..CRITICAL) + edge cases.
 *   3. Atomic creation of `alert_deliveries` for ERROR/CRITICAL with `webhook_url`,
 *      and absence of alerts when `webhook_url` is NULL/empty or level is non-alertable.
 *   4. Batch ingestion (`cerberus_ingest_batch`) success and full transactional rollback
 *      when any event fails C validation or SQLite CHECK constraints mid-transaction.
 *   5. End-to-end HTTP server (`--serve`) integration testing (`GET /health`, `POST /ingest`)
 *      and verification of SQLite persistence + FTS5 (`events_fts`) full-text indexing.
 */

#define _POSIX_C_SOURCE 200809L

#include "cerberus_ingestor.h"
#include "sqlite3.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST_DB_PATH     "build/qa_unit_test.db"
#define TEST_HTTP_DB     "build/qa_http_test.db"
#define TEST_SCHEMA_PATH "../schema/schema.sql"
#define INGESTOR_BIN     "./bin/cerberus-ingestor"

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond, msg)                                                              \
    do {                                                                                    \
        if (!(cond)) {                                                                      \
            fprintf(stderr, "  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg));             \
            g_tests_failed++;                                                               \
            return false;                                                                   \
        }                                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                                        \
    do {                                                                                    \
        g_tests_run++;                                                                      \
        fprintf(stdout, "[TEST %02d] %-58s ... ", g_tests_run, #fn);                        \
        fflush(stdout);                                                                     \
        if (fn()) {                                                                         \
            fprintf(stdout, "PASS\n");                                                      \
        } else {                                                                            \
            fprintf(stdout, "FAIL\n");                                                      \
        }                                                                                   \
    } while (0)

/* ============================================================================
 * Test Helpers
 * ============================================================================ */

static void remove_db_files(const char *base_path) {
    char wal[512];
    char shm[512];
    snprintf(wal, sizeof(wal), "%s-wal", base_path);
    snprintf(shm, sizeof(shm), "%s-shm", base_path);
    (void)unlink(base_path);
    (void)unlink(wal);
    (void)unlink(shm);
}

static int64_t query_int64(const char *db_path, const char *sql) {
    sqlite3 *conn = NULL;
    if (sqlite3_open_v2(db_path, &conn, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (conn) sqlite3_close(conn);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    int64_t result = -1;
    if (sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = (int64_t)sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(conn);
    return result;
}

/* ============================================================================
 * 1. Initialization & 0600 Permission Tests
 * ============================================================================ */

static bool test_init_and_0600_permissions(void) {
    remove_db_files(TEST_DB_PATH);

    /* Null pointer & empty path guards */
    cerberus_db_t *db = NULL;
    ASSERT_TRUE(cerberus_init(NULL, TEST_SCHEMA_PATH, &db) == CERBERUS_ERR_NULL_PTR,
                "cerberus_init(NULL) must return CERBERUS_ERR_NULL_PTR");
    ASSERT_TRUE(cerberus_init("", TEST_SCHEMA_PATH, &db) == CERBERUS_ERR_NULL_PTR,
                "cerberus_init(\"\") must return CERBERUS_ERR_NULL_PTR");
    ASSERT_TRUE(cerberus_init(TEST_DB_PATH, TEST_SCHEMA_PATH, NULL) == CERBERUS_ERR_NULL_PTR,
                "cerberus_init(..., NULL) must return CERBERUS_ERR_NULL_PTR");

    /* Pre-create file with overly permissive 0666 mode to verify cerberus_init tightens to 0600 */
    int fd = open(TEST_DB_PATH, O_CREAT | O_RDWR | O_TRUNC, 0666);
    ASSERT_TRUE(fd >= 0, "Failed to pre-create test DB file");
    (void)fchmod(fd, 0666);
    close(fd);

    cerberus_status_t st = cerberus_init(TEST_DB_PATH, TEST_SCHEMA_PATH, &db);
    ASSERT_TRUE(st == CERBERUS_OK && db != NULL, "cerberus_init failed with valid schema");

    struct stat sb;
    ASSERT_TRUE(stat(TEST_DB_PATH, &sb) == 0, "stat() failed on TEST_DB_PATH");
    mode_t perms = sb.st_mode & 0777;
    ASSERT_TRUE(perms == 0600, "Database file permissions must be strictly 0600");

    cerberus_close(db);
    remove_db_files(TEST_DB_PATH);
    return true;
}

/* ============================================================================
 * 2. All 5 Severity Levels & Input Validation Edge Cases
 * ============================================================================ */

static bool test_all_five_levels_and_validation(void) {
    remove_db_files(TEST_DB_PATH);

    cerberus_db_t *db = NULL;
    ASSERT_TRUE(cerberus_init(TEST_DB_PATH, TEST_SCHEMA_PATH, &db) == CERBERUS_OK,
                "cerberus_init failed");

    const char *levels[5] = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};
    for (int i = 0; i < 5; ++i) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Telemetry event for severity %s", levels[i]);
        cerberus_event_t ev = {
            .source = "sensor-node-alpha",
            .level = levels[i],
            .message = msg,
            .metadata_json = "{\"seq\":1,\"tag\":\"level_test\"}",
            .webhook_url = NULL
        };
        int64_t event_id = -1;
        cerberus_status_t st = cerberus_ingest_event(db, &ev, &event_id);
        ASSERT_TRUE(st == CERBERUS_OK, "Failed to ingest valid level event");
        ASSERT_TRUE(event_id == (int64_t)(i + 1), "Unexpected sequential event_id");
    }

    /* Verify all 5 levels are persisted in events and indexed in events_fts */
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events;") == 5,
                "Expected 5 rows in events");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'Telemetry';") == 5,
                "Expected 5 rows in events_fts matching 'Telemetry'");

    /* Defensive validation edge cases */
    cerberus_event_t bad_lvl = {
        .source = "src",
        .level = "TRACE",
        .message = "msg",
        .metadata_json = "{}",
        .webhook_url = NULL
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &bad_lvl, NULL) == CERBERUS_ERR_INVALID_LEVEL,
                "TRACE level must be rejected");

    cerberus_event_t empty_src = {
        .source = "",
        .level = "INFO",
        .message = "msg",
        .metadata_json = "{}",
        .webhook_url = NULL
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &empty_src, NULL) == CERBERUS_ERR_INVALID_SOURCE,
                "Empty source must be rejected");

    cerberus_event_t bad_meta = {
        .source = "src",
        .level = "INFO",
        .message = "msg",
        .metadata_json = "[1,2,3]",
        .webhook_url = NULL
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &bad_meta, NULL) == CERBERUS_ERR_INVALID_METADATA,
                "JSON array metadata must be rejected");

    cerberus_close(db);
    remove_db_files(TEST_DB_PATH);
    return true;
}

/* ============================================================================
 * 3. Atomic Alert Delivery Creation Rules
 * ============================================================================ */

static bool test_atomic_alert_deliveries_rules(void) {
    remove_db_files(TEST_DB_PATH);

    cerberus_db_t *db = NULL;
    ASSERT_TRUE(cerberus_init(TEST_DB_PATH, TEST_SCHEMA_PATH, &db) == CERBERUS_OK,
                "cerberus_init failed");

    /* Case A: ERROR with valid webhook_url -> creates 1 alert */
    cerberus_event_t ev_err_hook = {
        .source = "waf-01",
        .level = "ERROR",
        .message = "SQLi pattern blocked",
        .metadata_json = "{\"ip\":\"203.0.113.5\"}",
        .webhook_url = "https://127.0.0.1:8443/hooks/error"
    };
    int64_t id_err = -1;
    ASSERT_TRUE(cerberus_ingest_event(db, &ev_err_hook, &id_err) == CERBERUS_OK,
                "ERROR with webhook failed");

    /* Case B: CRITICAL with valid webhook_url -> creates 1 alert */
    cerberus_event_t ev_crit_hook = {
        .source = "waf-01",
        .level = "CRITICAL",
        .message = "Remote shell execution blocked",
        .metadata_json = "{\"ip\":\"203.0.113.9\"}",
        .webhook_url = "http://127.0.0.1:8080/hooks/critical"
    };
    int64_t id_crit = -1;
    ASSERT_TRUE(cerberus_ingest_event(db, &ev_crit_hook, &id_crit) == CERBERUS_OK,
                "CRITICAL with webhook failed");

    /* Case C: ERROR with NULL webhook_url -> NO alert */
    cerberus_event_t ev_err_null = {
        .source = "waf-01",
        .level = "ERROR",
        .message = "Error without webhook",
        .metadata_json = NULL,
        .webhook_url = NULL
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &ev_err_null, NULL) == CERBERUS_OK,
                "ERROR with NULL webhook failed");

    /* Case D: CRITICAL with empty "" webhook_url -> NO alert */
    cerberus_event_t ev_crit_empty = {
        .source = "waf-01",
        .level = "CRITICAL",
        .message = "Critical with empty webhook",
        .metadata_json = "{}",
        .webhook_url = ""
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &ev_crit_empty, NULL) == CERBERUS_OK,
                "CRITICAL with empty webhook failed");

    /* Case E: WARN with valid webhook_url -> NO alert (only ERROR/CRITICAL trigger alerts) */
    cerberus_event_t ev_warn_hook = {
        .source = "waf-01",
        .level = "WARN",
        .message = "Warn with webhook should not queue alert",
        .metadata_json = "{}",
        .webhook_url = "https://127.0.0.1:8443/hooks/warn"
    };
    ASSERT_TRUE(cerberus_ingest_event(db, &ev_warn_hook, NULL) == CERBERUS_OK,
                "WARN with webhook failed");

    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events;") == 5,
                "Expected 5 total events");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM alert_deliveries;") == 2,
                "Expected exactly 2 rows in alert_deliveries");
    ASSERT_TRUE(query_int64(TEST_DB_PATH,
                "SELECT COUNT(*) FROM alert_deliveries WHERE status='PENDING' AND attempts=0 AND max_attempts=3;") == 2,
                "Expected both alerts to have status=PENDING, attempts=0, max_attempts=3");

    char sql_Verify[256];
    snprintf(sql_Verify, sizeof(sql_Verify),
             "SELECT COUNT(*) FROM alert_deliveries WHERE event_id IN (%" PRId64 ", %" PRId64 ");",
             id_err, id_crit);
    ASSERT_TRUE(query_int64(TEST_DB_PATH, sql_Verify) == 2,
                "Alert deliveries must reference exact ERROR and CRITICAL event_ids");

    cerberus_close(db);
    remove_db_files(TEST_DB_PATH);
    return true;
}

/* ============================================================================
 * 4. Batch Ingestion & Atomic Rollback Tests
 * ============================================================================ */

static bool test_batch_ingest_and_atomic_rollback(void) {
    remove_db_files(TEST_DB_PATH);

    cerberus_db_t *db = NULL;
    ASSERT_TRUE(cerberus_init(TEST_DB_PATH, TEST_SCHEMA_PATH, &db) == CERBERUS_OK,
                "cerberus_init failed");

    /* Part 1: Valid batch of 4 events (including 1 CRITICAL with webhook) */
    cerberus_event_t valid_batch[4] = {
        {"batch-src", "DEBUG",    "Batch msg 1", "{\"i\":1}", NULL},
        {"batch-src", "INFO",     "Batch msg 2", "{\"i\":2}", NULL},
        {"batch-src", "WARN",     "Batch msg 3", "{\"i\":3}", NULL},
        {"batch-src", "CRITICAL", "Batch msg 4", "{\"i\":4}", "https://127.0.0.1:9443/alert"}
    };
    size_t inserted = 0;
    ASSERT_TRUE(cerberus_ingest_batch(db, valid_batch, 4, &inserted) == CERBERUS_OK,
                "Valid batch ingestion failed");
    ASSERT_TRUE(inserted == 4, "Expected out_inserted == 4");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events;") == 4,
                "Expected 4 events in DB after valid batch");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM alert_deliveries;") == 1,
                "Expected 1 alert in DB after valid batch");

    /* Part 2: Batch where the 3rd event fails C validation (invalid level) -> 0 inserted */
    cerberus_event_t c_invalid_batch[3] = {
        {"batch-src", "INFO",    "Should not persist 1", "{}", NULL},
        {"batch-src", "ERROR",   "Should not persist 2", "{}", "https://127.0.0.1:9443/alert2"},
        {"batch-src", "INVALID", "Bad level on 3rd item", "{}", NULL}
    };
    inserted = 99;
    ASSERT_TRUE(cerberus_ingest_batch(db, c_invalid_batch, 3, &inserted) == CERBERUS_ERR_INVALID_LEVEL,
                "Expected CERBERUS_ERR_INVALID_LEVEL for invalid batch item");
    ASSERT_TRUE(inserted == 0, "Expected out_inserted == 0 on failed batch");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events;") == 4,
                "Event count must remain 4 after C-level rejected batch");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM alert_deliveries;") == 1,
                "Alert count must remain 1 after C-level rejected batch");

    /* Part 3: Batch where event 1 & 2 insert inside BEGIN IMMEDIATE, and event 3 fails
     * SQLite CHECK(json_valid(metadata_json)) with "{malformed_json}" -> triggers SQL ROLLBACK! */
    cerberus_event_t sql_rollback_batch[3] = {
        {"batch-src", "INFO",     "Rollback test item 1", "{\"ok\":true}", NULL},
        {"batch-src", "CRITICAL", "Rollback test item 2", "{\"ok\":true}", "https://127.0.0.1:9443/alert3"},
        {"batch-src", "WARN",     "Rollback test item 3", "{malformed_json}", NULL}
    };
    inserted = 99;
    cerberus_status_t rb_st = cerberus_ingest_batch(db, sql_rollback_batch, 3, &inserted);
    ASSERT_TRUE(rb_st == CERBERUS_ERR_DB_CONSTRAINT,
                "Expected CERBERUS_ERR_DB_CONSTRAINT when SQLite json_valid CHECK fails mid-batch");
    ASSERT_TRUE(inserted == 0, "Expected out_inserted == 0 after SQLite rollback");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM events;") == 4,
                "Atomic rollback failed: event count changed after mid-batch failure");
    ASSERT_TRUE(query_int64(TEST_DB_PATH, "SELECT COUNT(*) FROM alert_deliveries;") == 1,
                "Atomic rollback failed: alert_deliveries count changed after mid-batch failure");

    cerberus_close(db);
    remove_db_files(TEST_DB_PATH);
    return true;
}

/* ============================================================================
 * 5. HTTP Server (--serve) End-to-End Integration Test
 * ============================================================================ */

static int send_raw_http_request(uint16_t port, const char *req, char *resp_buf, size_t resp_cap) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    size_t req_len = strlen(req);
    if (send(sock, req, req_len, 0) != (ssize_t)req_len) {
        close(sock);
        return -1;
    }

    size_t total = 0;
    while (total + 1 < resp_cap) {
        ssize_t n = recv(sock, resp_buf + total, resp_cap - 1 - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    resp_buf[total] = '\0';
    close(sock);
    return (int)total;
}

static bool test_http_server_integration_and_fts5(void) {
    remove_db_files(TEST_HTTP_DB);

    uint16_t port = 18941;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0, "fork() failed");

    if (pid == 0) {
        /* Child process: redirect stdout to /dev/null and exec cerberus-ingestor --serve */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        execl(INGESTOR_BIN, INGESTOR_BIN,
              "--db", TEST_HTTP_DB,
              "--schema", TEST_SCHEMA_PATH,
              "--serve", port_str,
              (char *)NULL);
        _exit(127);
    }

    /* Wait for the HTTP server to accept connections on 127.0.0.1:port */
    char resp[4096];
    bool ready = false;
    const char *health_req =
        "GET /health HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n";

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 25000000L}; /* 25ms */
    for (int attempt = 0; attempt < 40; ++attempt) {
        if (send_raw_http_request(port, health_req, resp, sizeof(resp)) > 0) {
            ready = true;
            break;
        }
        nanosleep(&ts, NULL);
    }

    if (!ready) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        ASSERT_TRUE(false, "HTTP server failed to start within timeout");
    }

    /* Verify GET /health response */
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 200 OK") != NULL, "GET /health did not return 200 OK");
    ASSERT_TRUE(strstr(resp, "\"status\":\"ok\"") != NULL &&
                strstr(resp, "\"service\":\"cerberus-ingestor\"") != NULL,
                "GET /health JSON body mismatch");

    /* Send POST /ingest with a CRITICAL event + webhook + nested JSON metadata */
    const char *post_body_1 =
        "{\"source\":\"ebpf-probe-07\","
        "\"level\":\"CRITICAL\","
        "\"message\":\"Unauthorized kernel module insmod rootkit_xyz detected\","
        "\"metadata\":{\"pid\":4192,\"uid\":0,\"comm\":\"insmod\"},"
        "\"webhook_url\":\"https://127.0.0.1:8443/soar/incident\"}";
    char post_req_1[1024];
    snprintf(post_req_1, sizeof(post_req_1),
             "POST /ingest HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             strlen(post_body_1), post_body_1);

    ASSERT_TRUE(send_raw_http_request(port, post_req_1, resp, sizeof(resp)) > 0,
                "POST /ingest (1) socket error");
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 201 Created") != NULL,
                "POST /ingest (1) did not return 201 Created");
    ASSERT_TRUE(strstr(resp, "\"event_id\":1") != NULL,
                "POST /ingest (1) did not return event_id:1");

    /* Send POST /ingest with an INFO event (no webhook) */
    const char *post_body_2 =
        "{\"source\":\"sshd-bastion\","
        "\"level\":\"INFO\","
        "\"message\":\"Accepted publickey for admin from 10.20.30.40 port 51234 ssh2\"}";
    char post_req_2[1024];
    snprintf(post_req_2, sizeof(post_req_2),
             "POST /ingest HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             strlen(post_body_2), post_body_2);

    ASSERT_TRUE(send_raw_http_request(port, post_req_2, resp, sizeof(resp)) > 0,
                "POST /ingest (2) socket error");
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 201 Created") != NULL,
                "POST /ingest (2) did not return 201 Created");
    ASSERT_TRUE(strstr(resp, "\"event_id\":2") != NULL,
                "POST /ingest (2) did not return event_id:2");

    /* Send invalid POST /ingest (SSRF webhook) and verify 400 Bad Request */
    const char *post_body_ssrf =
        "{\"source\":\"sshd-bastion\","
        "\"level\":\"ERROR\","
        "\"message\":\"Attempted SSRF webhook\","
        "\"webhook_url\":\"http://169.254.169.254/latest/meta-data/\"}";
    char post_req_ssrf[1024];
    snprintf(post_req_ssrf, sizeof(post_req_ssrf),
             "POST /ingest HTTP/1.1\r\n"
             "Host: 127.0.0.1\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n%s",
             strlen(post_body_ssrf), post_body_ssrf);

    ASSERT_TRUE(send_raw_http_request(port, post_req_ssrf, resp, sizeof(resp)) > 0,
                "POST /ingest (SSRF) socket error");
    ASSERT_TRUE(strstr(resp, "HTTP/1.1 400 Bad Request") != NULL,
                "POST /ingest (SSRF) must return 400 Bad Request");

    /* Stop server cleanly via SIGTERM */
    kill(pid, SIGTERM);
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);

    /* Verify persisted rows in SQLite and FTS5 index */
    ASSERT_TRUE(query_int64(TEST_HTTP_DB, "SELECT COUNT(*) FROM events;") == 2,
                "Expected 2 events persisted by HTTP server");
    ASSERT_TRUE(query_int64(TEST_HTTP_DB, "SELECT COUNT(*) FROM alert_deliveries WHERE event_id=1 AND status='PENDING';") == 1,
                "Expected 1 PENDING alert_delivery for event_id=1");
    ASSERT_TRUE(query_int64(TEST_HTTP_DB, "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'rootkit_xyz';") == 1,
                "FTS5 search for 'rootkit_xyz' failed");
    ASSERT_TRUE(query_int64(TEST_HTTP_DB, "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'publickey';") == 1,
                "FTS5 search for 'publickey' failed");

    remove_db_files(TEST_HTTP_DB);
    return true;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void) {
    fprintf(stdout, "==============================================================================\n");
    fprintf(stdout, " Cerberus Head 1 (C11 Ingestor) — QA Unit & Integration Test Suite\n");
    fprintf(stdout, "==============================================================================\n");

    RUN_TEST(test_init_and_0600_permissions);
    RUN_TEST(test_all_five_levels_and_validation);
    RUN_TEST(test_atomic_alert_deliveries_rules);
    RUN_TEST(test_batch_ingest_and_atomic_rollback);
    RUN_TEST(test_http_server_integration_and_fts5);

    fprintf(stdout, "==============================================================================\n");
    fprintf(stdout, " Results: %d/%d tests passed (%d failed)\n",
            g_tests_run - g_tests_failed, g_tests_run, g_tests_failed);
    fprintf(stdout, "==============================================================================\n");

    return (g_tests_failed == 0) ? 0 : 1;
}
