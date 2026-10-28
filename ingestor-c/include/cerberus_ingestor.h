/**
 * @file cerberus_ingestor.h
 * @brief Cerberus Head 1 — High-Throughput C11 Telemetry & Security Event Ingestor
 *
 * Provides a hardened, modular C11 API for ingesting security telemetry into the
 * shared SQLite3 (WAL + FTS5) database using precompiled prepared statements and
 * strict defensive input validation.
 */

#ifndef CERBERUS_INGESTOR_H
#define CERBERUS_INGESTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Domain Constants & Limits (Aligned with schema/schema.sql)
 * ============================================================================ */

#define CERBERUS_MAX_SOURCE_LEN       128U
#define CERBERUS_MAX_LEVEL_LEN        16U
#define CERBERUS_MAX_MESSAGE_LEN      8192U
#define CERBERUS_MAX_METADATA_LEN     16384U
#define CERBERUS_MIN_WEBHOOK_URL_LEN  10U
#define CERBERUS_MAX_WEBHOOK_URL_LEN  1024U
#define CERBERUS_DEFAULT_MAX_ATTEMPTS 3
#define CERBERUS_MAX_BATCH_SIZE       10000U

/* ============================================================================
 * Status Codes & Types
 * ============================================================================ */

typedef enum {
    CERBERUS_OK = 0,
    CERBERUS_ERR_NULL_PTR = 1,
    CERBERUS_ERR_INVALID_SOURCE = 2,
    CERBERUS_ERR_INVALID_LEVEL = 3,
    CERBERUS_ERR_INVALID_MESSAGE = 4,
    CERBERUS_ERR_INVALID_METADATA = 5,
    CERBERUS_ERR_INVALID_WEBHOOK = 6,
    CERBERUS_ERR_IO = 7,
    CERBERUS_ERR_DB_OPEN = 8,
    CERBERUS_ERR_DB_SCHEMA = 9,
    CERBERUS_ERR_DB_PREPARE = 10,
    CERBERUS_ERR_DB_EXEC = 11,
    CERBERUS_ERR_DB_CONSTRAINT = 12,
    CERBERUS_ERR_NOMEM = 13,
    CERBERUS_ERR_CANCELLED = 14
} cerberus_status_t;

/**
 * @brief Opaque database and precompiled statement handle.
 */
typedef struct cerberus_db cerberus_db_t;

/**
 * @brief Input structure representing a single security or telemetry event.
 */
typedef struct {
    const char *source;        /**< Event source identifier (1..128 bytes) */
    const char *level;         /**< Severity: DEBUG, INFO, WARN, ERROR, CRITICAL */
    const char *message;       /**< Event description/log message (1..8192 bytes) */
    const char *metadata_json; /**< Optional JSON object string (NULL defaults to "{}") */
    const char *webhook_url;   /**< Optional HTTP/HTTPS webhook target for ERROR/CRITICAL */
} cerberus_event_t;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * @brief Returns a human-readable static string describing a status code.
 */
const char *cerberus_status_str(cerberus_status_t status);

/**
 * @brief Returns the last extended error message stored in the database handle.
 */
const char *cerberus_last_error(const cerberus_db_t *db);

/**
 * @brief Validates an event defensively in C before touching SQLite.
 */
cerberus_status_t cerberus_validate_event(const cerberus_event_t *event);

/**
 * @brief Returns the length (1..4) of the well-formed UTF-8 sequence at `p`
 *        (RFC 3629: no overlongs, no surrogates, <= U+10FFFF), or 0 if invalid.
 */
size_t cerberus_utf8_seq_len(const unsigned char *p, size_t avail);

/**
 * @brief Returns 1 if `s[0..len)` is entirely well-formed UTF-8, else 0.
 */
int cerberus_utf8_valid(const char *s, size_t len);

/**
 * @brief Initializes the SQLite database connection, enforces 0600 file permissions,
 *        applies the schema/PRAGMAs, and precompiles all prepared statements.
 *
 * @param db_path     Plain path to the SQLite database file, or ":memory:".
 *                    SQLite URIs ("file:...") are rejected with CERBERUS_ERR_DB_OPEN.
 * @param schema_path Optional path to schema.sql (if NULL, uses embedded fallback).
 * @param out_db      Output pointer receiving the initialized cerberus_db_t handle.
 * @return CERBERUS_OK on success, or an error status code.
 */
cerberus_status_t cerberus_init(const char *db_path, const char *schema_path, cerberus_db_t **out_db);

/**
 * @brief Ingests a single event into `events` (and optionally `alert_deliveries`
 *        within an atomic IMMEDIATE transaction if level is ERROR/CRITICAL and
 *        `webhook_url` is provided).
 *
 * @param db           Initialized Cerberus database handle.
 * @param event        Pointer to the event to ingest.
 * @param out_event_id Optional output pointer to receive the inserted row ID.
 * @return CERBERUS_OK on success, or an error status code.
 */
cerberus_status_t cerberus_ingest_event(cerberus_db_t *db, const cerberus_event_t *event, int64_t *out_event_id);

/**
 * @brief Ingests a batch of events inside a single atomic `BEGIN IMMEDIATE`
 *        transaction. If any event fails validation or insertion, the entire
 *        batch is rolled back.
 *
 * @param db           Initialized Cerberus database handle.
 * @param events       Array of events of length `count`.
 * @param count        Number of events in the array.
 * @param out_inserted Optional output pointer receiving the count of inserted events.
 * @return CERBERUS_OK on success, or an error status code.
 */
cerberus_status_t cerberus_ingest_batch(cerberus_db_t *db, const cerberus_event_t *events, size_t count, size_t *out_inserted);

/**
 * @brief Cancels pending and future work on `db` (used during shutdown).
 *
 * Thread-safe: may be called while another thread is inside
 * cerberus_ingest_event()/cerberus_ingest_batch(). A running statement is
 * interrupted, a wait on a locked database stops immediately and every later
 * ingest returns CERBERUS_ERR_CANCELLED. It does NOT free the handle: the
 * caller must still make sure no thread uses `db` before cerberus_close().
 */
void cerberus_interrupt(cerberus_db_t *db);

/**
 * @brief Finalizes all prepared statements and closes the SQLite connection cleanly.
 *
 * @param db Initialized Cerberus database handle (safe to pass NULL).
 */
void cerberus_close(cerberus_db_t *db);

#ifdef __cplusplus
}
#endif

#endif /* CERBERUS_INGESTOR_H */
