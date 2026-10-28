//! Cerberus Head 3 — Full-Text Search (FTS5) & Analytics Engine.
//!
//! Provides safe, parameterized SQLite FTS5 search with BM25 ranking,
//! snippet extraction, and real-time operational metrics aggregation.

use rusqlite::{params, params_from_iter, types::Value, Connection};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

/// Maximum allowed length in characters/bytes for a user search query.
pub const MAX_QUERY_LEN: usize = 256;
/// Maximum allowed number of tokens in a single FTS5 search query to prevent intersection DoS.
pub const MAX_QUERY_TOKENS: usize = 16;
/// Maximum allowed length for a source filter.
pub const MAX_SOURCE_LEN: usize = 128;
/// Default pagination limit.
pub const DEFAULT_LIMIT: usize = 20;
/// Maximum pagination limit.
pub const MAX_LIMIT: usize = 100;
/// Maximum pagination offset to prevent deep-scan DoS and `usize` -> `i64` integer overflow.
pub const MAX_OFFSET: usize = 100_000;

/// Valid severity levels supported by Cerberus.
pub const VALID_LEVELS: [&str; 5] = ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"];

/// Domain error type for search and analytics operations.
#[derive(Debug)]
pub enum SearchError {
    /// Invalid user input or query parameter.
    ValidationError(String),
    /// SQLite database error.
    DatabaseError(rusqlite::Error),
    /// Filesystem or I/O error.
    IoError(std::io::Error),
    /// JSON serialization/deserialization error.
    SerializationError(serde_json::Error),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SearchError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            SearchError::DatabaseError(err) => write!(f, "Database error: {}", err),
            SearchError::IoError(err) => write!(f, "I/O error: {}", err),
            SearchError::SerializationError(err) => write!(f, "Serialization error: {}", err),
        }
    }
}

impl std::error::Error for SearchError {}

impl From<rusqlite::Error> for SearchError {
    fn from(err: rusqlite::Error) -> Self {
        SearchError::DatabaseError(err)
    }
}

impl From<std::io::Error> for SearchError {
    fn from(err: std::io::Error) -> Self {
        SearchError::IoError(err)
    }
}

impl From<serde_json::Error> for SearchError {
    fn from(err: serde_json::Error) -> Self {
        SearchError::SerializationError(err)
    }
}

/// Parameters for searching events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Optional full-text search query (matched via FTS5).
    pub query: Option<String>,
    /// Optional exact severity level filter (`DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL`).
    pub level: Option<String>,
    /// Optional exact source filter.
    pub source: Option<String>,
    /// Maximum number of results to return (`1..=100`, default `20`).
    pub limit: usize,
    /// Pagination offset.
    pub offset: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            query: None,
            level: None,
            source: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
        }
    }
}

/// A single matching event returned by [`SearchEngine::search_events`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResultItem {
    pub id: i64,
    pub source: String,
    pub level: String,
    pub message: String,
    pub snippet: String,
    pub metadata_json: String,
    pub created_at: i64,
    pub rank: f64,
}

/// Complete response from a search operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResponse {
    pub sanitized_query: Option<String>,
    pub level: Option<String>,
    pub source: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub count: usize,
    pub total_matches: usize,
    pub results: Vec<SearchResultItem>,
}

/// Event counts broken down by severity level.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LevelCounts {
    pub debug: u64,
    pub info: u64,
    pub warn: u64,
    pub error: u64,
    pub critical: u64,
}

/// Count of events originating from a specific source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceCount {
    pub source: String,
    pub count: u64,
}

/// Summary of alert delivery queue states.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertSummary {
    pub total: u64,
    pub pending: u64,
    pub sent: u64,
    pub failed: u64,
    pub dead: u64,
}

/// Global system summary combining event and alert analytics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemSummary {
    pub total_events: u64,
    pub events_by_level: LevelCounts,
    pub top_sources: Vec<SourceCount>,
    pub alerts: AlertSummary,
}

/// Sanitizes an arbitrary user query string into a safe FTS5 `MATCH` expression.
///
/// # Security Design
/// In SQLite FTS5, characters like `"`, `*`, `(`, `)`, `:`, `^`, `-` or keywords
/// such as `NEAR`, `AND`, `OR`, `NOT` can trigger FTS5 syntax errors or allow
/// query operator injection if raw user input is passed directly to `MATCH`.
///
/// This function:
/// 1. Rejects empty queries or queries longer than [`MAX_QUERY_LEN`] (256 bytes/chars).
/// 2. Splits input into alphanumeric/underscore/hyphen/dot tokens, stripping any
///    FTS5 special operators (`"`, `(`, `)`, `:`, `^`, etc.).
/// 3. Supports a safe trailing prefix wildcard (`*`) only when attached to the end
///    of a valid alphanumeric token (e.g., `"auth"*`).
/// 4. Wraps every token in double quotes `"token"` so FTS5 reserved words (`NEAR`,
///    `AND`, `OR`, `NOT`) and punctuation are treated strictly as literal terms.
pub fn sanitize_fts5_query(raw: &str) -> Result<String, SearchError> {
    if raw.contains('\0') {
        return Err(SearchError::ValidationError(
            "Search query contains invalid null byte".to_string(),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SearchError::ValidationError(
            "Search query cannot be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_QUERY_LEN {
        return Err(SearchError::ValidationError(format!(
            "Search query exceeds maximum length of {} bytes",
            MAX_QUERY_LEN
        )));
    }

    let mut safe_tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            // Avoid leading hyphens or dots inside a token
            if current.is_empty() && (ch == '-' || ch == '.') {
                continue;
            }
            current.push(ch);
        } else if ch == '*' && !current.is_empty() {
            // Trailing prefix wildcard on a valid non-empty token
            let next_is_boundary = match chars.peek() {
                None => true,
                Some(next_ch) => !next_ch.is_alphanumeric() && *next_ch != '_',
            };
            let cleaned = current.trim_end_matches(['-', '.']);
            if !cleaned.is_empty() {
                if next_is_boundary {
                    safe_tokens.push(format!("\"{}\"*", cleaned));
                } else {
                    safe_tokens.push(format!("\"{}\"", cleaned));
                }
            }
            current.clear();
        } else if !current.is_empty() {
            let cleaned = current.trim_end_matches(['-', '.']);
            if !cleaned.is_empty() {
                safe_tokens.push(format!("\"{}\"", cleaned));
            }
            current.clear();
        }
    }

    if !current.is_empty() {
        let cleaned = current.trim_end_matches(['-', '.']);
        if !cleaned.is_empty() {
            safe_tokens.push(format!("\"{}\"", cleaned));
        }
    }

    if safe_tokens.is_empty() {
        return Err(SearchError::ValidationError(
            "Search query contains no valid searchable tokens".to_string(),
        ));
    }

    if safe_tokens.len() > MAX_QUERY_TOKENS {
        return Err(SearchError::ValidationError(format!(
            "Search query exceeds maximum of {} tokens",
            MAX_QUERY_TOKENS
        )));
    }

    Ok(safe_tokens.join(" "))
}

/// Validates and normalizes an event severity level.
pub fn validate_level(level: &str) -> Result<String, SearchError> {
    if level.contains('\0') || level.chars().any(|c| c.is_control()) {
        return Err(SearchError::ValidationError(
            "Level filter contains invalid control characters".to_string(),
        ));
    }
    let normalized = level.trim().to_ascii_uppercase();
    if VALID_LEVELS.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(SearchError::ValidationError(format!(
            "Invalid level '{}': expected one of DEBUG, INFO, WARN, ERROR, CRITICAL",
            level
        )))
    }
}

/// Validates a source filter string.
pub fn validate_source(source: &str) -> Result<String, SearchError> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(SearchError::ValidationError(
            "Source filter cannot be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_SOURCE_LEN {
        return Err(SearchError::ValidationError(format!(
            "Source filter exceeds maximum length of {} bytes",
            MAX_SOURCE_LEN
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(SearchError::ValidationError(
            "Source filter contains invalid control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Reads a TEXT column tolerating invalid UTF-8 (legacy rows): invalid bytes
/// become U+FFFD instead of failing the whole query.
fn text_lossy(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<String> {
    use rusqlite::types::ValueRef;
    match row.get_ref(idx)? {
        ValueRef::Text(b) | ValueRef::Blob(b) => Ok(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Null => Ok(String::new()),
        ValueRef::Integer(i) => Ok(i.to_string()),
        ValueRef::Real(r) => Ok(r.to_string()),
    }
}

/// Common file policy for all three heads: the database file (and its
/// `-wal`/`-shm` companions) must be private to the owner (0600).
#[cfg(unix)]
fn ensure_private_db_file(path: &Path) -> Result<(), SearchError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let s = path.to_string_lossy();
    // Only the exact ":memory:" name is exempt. A prefix test is not enough:
    // SQLite reads "file::memory:disk" as the FILE ":memory:disk".
    if s == ":memory:" {
        return Ok(());
    }
    // rusqlite opens with SQLITE_OPEN_URI: "file:x.db" would make SQLite use
    // "x.db" while this function protected a file literally named "file:x.db".
    // Every URI (file::memory: included) is refused instead of guessing its
    // real target; use ":memory:" for an in-memory database.
    if s.starts_with("file:") {
        return Err(SearchError::ValidationError(format!(
            "SQLite URIs are not supported for the database path ({s}); pass a plain filesystem path"
        )));
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn tighten_companion_files(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
    }
}

#[cfg(not(unix))]
fn ensure_private_db_file(_path: &Path) -> Result<(), SearchError> {
    Ok(())
}

#[cfg(not(unix))]
fn tighten_companion_files(_path: &Path) {}

/// Core SQLite FTS5 Search & Analytics Engine.
pub struct SearchEngine {
    conn: Connection,
}

impl SearchEngine {
    /// Opens a SQLite database at `db_path`, configures WAL concurrency pragmas,
    /// and optionally applies the DDL schema from `schema_path`.
    pub fn open<P: AsRef<Path>>(
        db_path: P,
        schema_path: Option<&Path>,
    ) -> Result<Self, SearchError> {
        let db_path = db_path.as_ref();
        ensure_private_db_file(db_path)?;
        let conn = Connection::open(db_path)?;
        Self::configure_pragmas(&conn)?;
        tighten_companion_files(db_path);

        let engine = Self { conn };
        if let Some(path) = schema_path {
            engine.apply_schema_file(path)?;
        }
        Ok(engine)
    }

    /// Creates an in-memory `SearchEngine` and applies the given SQL schema string.
    pub fn open_in_memory(schema_sql: &str) -> Result<Self, SearchError> {
        let conn = Connection::open_in_memory()?;
        Self::configure_pragmas(&conn)?;
        conn.execute_batch(schema_sql)?;
        Ok(Self { conn })
    }

    fn configure_pragmas(conn: &Connection) -> Result<(), SearchError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    }

    /// Reads and executes a SQL schema file on the underlying connection.
    pub fn apply_schema_file<P: AsRef<Path>>(&self, schema_path: P) -> Result<(), SearchError> {
        let sql = fs::read_to_string(schema_path)?;
        self.conn.execute_batch(&sql)?;
        Ok(())
    }

    /// Exposes a reference to the underlying SQLite connection (useful for seeding tests).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Searches events using FTS5 BM25 ranking and optional `level`/`source` filters.
    ///
    /// When `params.query` is provided:
    /// - Sanitizes the query via [`sanitize_fts5_query`].
    /// - Executes a parameterized `JOIN` between `events_fts` and `events`.
    /// - Computes `bm25(events_fts)` relevance score and `snippet(events_fts, 2, '[', ']', '...', 16)`.
    ///
    /// When `params.query` is `None`:
    /// - Returns recent events filtered by `level` and/or `source`, ordered by `created_at DESC, id DESC`.
    pub fn search_events(&self, params: &SearchQuery) -> Result<SearchResponse, SearchError> {
        if params.limit == 0 || params.limit > MAX_LIMIT {
            return Err(SearchError::ValidationError(format!(
                "Limit must be between 1 and {}, got {}",
                MAX_LIMIT, params.limit
            )));
        }
        let limit = params.limit;
        if params.offset > MAX_OFFSET {
            return Err(SearchError::ValidationError(format!(
                "Offset exceeds maximum allowed value of {}",
                MAX_OFFSET
            )));
        }
        let offset = params.offset;

        let sanitized_query = match &params.query {
            Some(q) if q.contains('\0') => {
                return Err(SearchError::ValidationError(
                    "Search query contains invalid null byte".to_string(),
                ))
            }
            Some(q) if !q.trim().is_empty() => Some(sanitize_fts5_query(q)?),
            Some(_) => {
                return Err(SearchError::ValidationError(
                    "Search query cannot be empty".to_string(),
                ))
            }
            None => None,
        };

        let normalized_level = match &params.level {
            Some(lvl) if lvl.contains('\0') => {
                return Err(SearchError::ValidationError(
                    "Level filter contains invalid null byte".to_string(),
                ))
            }
            Some(lvl) if !lvl.trim().is_empty() => Some(validate_level(lvl)?),
            Some(_) => {
                return Err(SearchError::ValidationError(
                    "Level filter cannot be empty".to_string(),
                ))
            }
            None => None,
        };

        let normalized_source = match &params.source {
            Some(src) if src.contains('\0') => {
                return Err(SearchError::ValidationError(
                    "Source filter contains invalid null byte".to_string(),
                ))
            }
            Some(src) if !src.trim().is_empty() => Some(validate_source(src)?),
            Some(_) => {
                return Err(SearchError::ValidationError(
                    "Source filter cannot be empty".to_string(),
                ))
            }
            None => None,
        };

        let mut results = Vec::new();
        let total_matches: usize;

        if let Some(ref fts_query) = sanitized_query {
            let mut where_clause = String::from(
                "FROM events_fts
                 INNER JOIN events e ON e.id = events_fts.rowid
                 WHERE events_fts MATCH ?1",
            );

            let mut bind_values: Vec<Value> = vec![Value::Text(fts_query.clone())];
            let mut param_idx = 2;

            if let Some(ref lvl) = normalized_level {
                where_clause.push_str(&format!(" AND e.level = ?{}", param_idx));
                bind_values.push(Value::Text(lvl.clone()));
                param_idx += 1;
            }

            if let Some(ref src) = normalized_source {
                where_clause.push_str(&format!(" AND e.source = ?{}", param_idx));
                bind_values.push(Value::Text(src.clone()));
                param_idx += 1;
            }

            let count_sql = format!("SELECT COUNT(*) {}", where_clause);
            let total_i64: i64 = self.conn.query_row(
                &count_sql,
                params_from_iter(bind_values.iter()),
                |row| row.get(0),
            )?;
            total_matches = total_i64.max(0) as usize;

            let sql = format!(
                "SELECT
                    e.id,
                    e.source,
                    e.level,
                    e.message,
                    snippet(events_fts, 2, '[', ']', '...', 16) AS snippet,
                    e.metadata_json,
                    e.created_at,
                    bm25(events_fts) AS rank
                 {} ORDER BY rank ASC, e.created_at DESC, e.id DESC LIMIT ?{} OFFSET ?{}",
                where_clause,
                param_idx,
                param_idx + 1
            );
            bind_values.push(Value::Integer(limit as i64));
            bind_values.push(Value::Integer(offset as i64));

            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(bind_values.iter()), |row| {
                Ok(SearchResultItem {
                    id: row.get(0)?,
                    source: text_lossy(row, 1)?,
                    level: text_lossy(row, 2)?,
                    message: text_lossy(row, 3)?,
                    snippet: text_lossy(row, 4)?,
                    metadata_json: text_lossy(row, 5)?,
                    created_at: row.get(6)?,
                    rank: row.get(7)?,
                })
            })?;

            for item in rows {
                results.push(item?);
            }
        } else {
            let mut where_clause = String::from("FROM events e WHERE 1=1");

            let mut bind_values: Vec<Value> = Vec::new();
            let mut param_idx = 1;

            if let Some(ref lvl) = normalized_level {
                where_clause.push_str(&format!(" AND e.level = ?{}", param_idx));
                bind_values.push(Value::Text(lvl.clone()));
                param_idx += 1;
            }

            if let Some(ref src) = normalized_source {
                where_clause.push_str(&format!(" AND e.source = ?{}", param_idx));
                bind_values.push(Value::Text(src.clone()));
                param_idx += 1;
            }

            let count_sql = format!("SELECT COUNT(*) {}", where_clause);
            let total_i64: i64 = self.conn.query_row(
                &count_sql,
                params_from_iter(bind_values.iter()),
                |row| row.get(0),
            )?;
            total_matches = total_i64.max(0) as usize;

            let sql = format!(
                "SELECT
                    e.id,
                    e.source,
                    e.level,
                    e.message,
                    e.message AS snippet,
                    e.metadata_json,
                    e.created_at,
                    0.0 AS rank
                 {} ORDER BY e.created_at DESC, e.id DESC LIMIT ?{} OFFSET ?{}",
                where_clause,
                param_idx,
                param_idx + 1
            );
            bind_values.push(Value::Integer(limit as i64));
            bind_values.push(Value::Integer(offset as i64));

            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(bind_values.iter()), |row| {
                Ok(SearchResultItem {
                    id: row.get(0)?,
                    source: text_lossy(row, 1)?,
                    level: text_lossy(row, 2)?,
                    message: text_lossy(row, 3)?,
                    snippet: text_lossy(row, 4)?,
                    metadata_json: text_lossy(row, 5)?,
                    created_at: row.get(6)?,
                    rank: row.get(7)?,
                })
            })?;

            for item in rows {
                results.push(item?);
            }
        }

        let count = results.len();
        Ok(SearchResponse {
            sanitized_query,
            level: normalized_level,
            source: normalized_source,
            limit,
            offset,
            count,
            total_matches,
            results,
        })
    }

    /// Computes a full operational summary of events by level, top sources, and alert deliveries.
    pub fn get_summary(&self) -> Result<SystemSummary, SearchError> {
        let mut level_counts = LevelCounts::default();
        let mut total_events: u64 = 0;

        {
            let mut stmt = self
                .conn
                .prepare("SELECT level, COUNT(*) FROM events GROUP BY level")?;
            let rows = stmt.query_map(params![], |row| {
                let level: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((level, count.max(0) as u64))
            })?;

            for row in rows {
                let (lvl, count) = row?;
                total_events = total_events.saturating_add(count);
                match lvl.as_str() {
                    "DEBUG" => level_counts.debug = count,
                    "INFO" => level_counts.info = count,
                    "WARN" => level_counts.warn = count,
                    "ERROR" => level_counts.error = count,
                    "CRITICAL" => level_counts.critical = count,
                    _ => {}
                }
            }
        }

        let mut top_sources = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT source, COUNT(*) AS cnt
                 FROM events
                 GROUP BY source
                 ORDER BY cnt DESC, source ASC
                 LIMIT 10",
            )?;
            let rows = stmt.query_map(params![], |row| {
                let source: String = text_lossy(row, 0)?;
                let count: i64 = row.get(1)?;
                Ok(SourceCount {
                    source,
                    count: count.max(0) as u64,
                })
            })?;

            for row in rows {
                top_sources.push(row?);
            }
        }

        let mut alerts = AlertSummary::default();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT status, COUNT(*) FROM alert_deliveries GROUP BY status")?;
            let rows = stmt.query_map(params![], |row| {
                let status: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((status, count.max(0) as u64))
            })?;

            for row in rows {
                let (status, count) = row?;
                alerts.total = alerts.total.saturating_add(count);
                match status.as_str() {
                    "PENDING" => alerts.pending = count,
                    "SENT" => alerts.sent = count,
                    "FAILED" => alerts.failed = count,
                    "DEAD" => alerts.dead = count,
                    _ => {}
                }
            }
        }

        Ok(SystemSummary {
            total_events,
            events_by_level: level_counts,
            top_sources,
            alerts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCHEMA: &str = include_str!("../../schema/schema.sql");

    fn setup_seeded_engine() -> Result<SearchEngine, SearchError> {
        let engine = SearchEngine::open_in_memory(TEST_SCHEMA)?;
        let conn = engine.connection();

        conn.execute(
            "INSERT INTO events (source, level, message, metadata_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "auth-service",
                "ERROR",
                "Failed password authentication for root user from 10.0.0.42",
                r#"{"ip":"10.0.0.42","user":"root"}"#,
                1700000001_i64
            ],
        )?;

        conn.execute(
            "INSERT INTO events (source, level, message, metadata_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "payment-gateway",
                "CRITICAL",
                "Database connection timeout while committing transaction TX998",
                r#"{"tx":"TX998","retry":3}"#,
                1700000002_i64
            ],
        )?;

        conn.execute(
            "INSERT INTO events (source, level, message, metadata_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "auth-service",
                "INFO",
                "User session token refreshed successfully",
                r#"{"user":"alice"}"#,
                1700000003_i64
            ],
        )?;

        conn.execute(
            "INSERT INTO alert_deliveries (event_id, target_url, status, attempts, max_attempts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1_i64, "http://127.0.0.1:9000/webhook", "SENT", 1_i64, 3_i64],
        )?;

        conn.execute(
            "INSERT INTO alert_deliveries (event_id, target_url, status, attempts, max_attempts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                2_i64,
                "http://127.0.0.1:9000/webhook",
                "PENDING",
                0_i64,
                3_i64
            ],
        )?;

        Ok(engine)
    }

    #[test]
    fn test_sanitize_fts5_query_valid_and_prefix() {
        let q = sanitize_fts5_query("password auth*").unwrap_or_default();
        assert_eq!(q, "\"password\" \"auth\"*");
    }

    #[test]
    fn test_sanitize_fts5_query_strips_malicious_operators() {
        let malicious = r#"root") OR NEAR(a, b) AND level:CRITICAL ^5 -drop * (test)"#;
        let sanitized = sanitize_fts5_query(malicious).unwrap_or_default();
        assert_eq!(
            sanitized,
            "\"root\" \"OR\" \"NEAR\" \"a\" \"b\" \"AND\" \"level\" \"CRITICAL\" \"5\" \"drop\" \"test\""
        );
    }

    #[test]
    fn test_sanitize_fts5_query_rejects_empty_or_only_symbols() {
        assert!(sanitize_fts5_query("   ").is_err());
        assert!(sanitize_fts5_query("\"*()^:---").is_err());
        let too_long = "a".repeat(MAX_QUERY_LEN + 1);
        assert!(sanitize_fts5_query(&too_long).is_err());
    }

    #[test]
    fn test_fts5_search_and_bm25_snippets() -> Result<(), SearchError> {
        let engine = setup_seeded_engine()?;

        let response = engine.search_events(&SearchQuery {
            query: Some("authentication root".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })?;

        assert_eq!(response.count, 1);
        let item = &response.results[0];
        assert_eq!(item.source, "auth-service");
        assert_eq!(item.level, "ERROR");
        assert!(item.snippet.contains("[authentication]") || item.snippet.contains("[root]"));
        assert!(item.rank < 0.0);
        Ok(())
    }

    #[test]
    fn test_search_with_hostile_fts_input_never_errors_in_sqlite() -> Result<(), SearchError> {
        let engine = setup_seeded_engine()?;

        let response = engine.search_events(&SearchQuery {
            query: Some(r#"unbalanced "quote (NEAR : ^ * -- password"#.to_string()),
            level: Some("error".to_string()),
            source: Some("auth-service".to_string()),
            limit: 10,
            offset: 0,
        })?;

        assert_eq!(response. results.len(), 0);
        Ok(())
    }

    #[test]
    fn test_get_summary_metrics() -> Result<(), SearchError> {
        let engine = setup_seeded_engine()?;
        let summary = engine.get_summary()?;

        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.events_by_level.error, 1);
        assert_eq!(summary.events_by_level.critical, 1);
        assert_eq!(summary.events_by_level.info, 1);
        assert_eq!(summary.events_by_level.debug, 0);
        assert_eq!(summary.top_sources.len(), 2);
        assert_eq!(summary.top_sources[0].source, "auth-service");
        assert_eq!(summary.top_sources[0].count, 2);
        assert_eq!(summary.alerts.total, 2);
        assert_eq!(summary.alerts.sent, 1);
        assert_eq!(summary.alerts.pending, 1);
        Ok(())
    }
}
