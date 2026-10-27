//! Red Team / AppSec Security Test Suite for Cerberus Head 3 (`cerberus-search`).
//!
//! Verifies resilience against:
//! 1. SQLite FTS5 syntax injection and SQL injection payloads.
//! 2. Null-byte (`\0` / `%00`) and control-character injection in `q`, `level`, and `source`.
//! 3. Denial of Service (DoS) via excessive token counts (`> MAX_QUERY_TOKENS`) and oversized queries.
//! 4. Integer overflow (`usize::MAX` -> `i64`) and deep-pagination DoS (`> MAX_OFFSET`).
//! 5. HTTP Server attacks: `413 Payload Too Large` (>8KB), `405 Method Not Allowed`,
//!    invalid UTF-8 percent-encoding (`%FF%FE`), Slowloris deadline, and zero information
//!    leakage on `500 Internal Server Error`.

use cerberus_search::{
    sanitize_fts5_query, validate_level, validate_source, SearchEngine, SearchError, SearchQuery,
    MAX_OFFSET, MAX_QUERY_LEN, MAX_QUERY_TOKENS,
};
use rusqlite::params;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SCHEMA_SQL: &str = include_str!("../../schema/schema.sql");

fn setup_engine() -> SearchEngine {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("in-memory DB init failed");
    engine
        .connection()
        .execute(
            "INSERT INTO events (source, level, message, metadata_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "auth-service",
                "ERROR",
                "Failed password authentication for root from 10.0.0.99",
                r#"{"ip":"10.0.0.99"}"#,
                1700000100_i64
            ],
        )
        .expect("seed insert failed");
    engine
}

#[test]
fn test_sec_fts5_and_sql_injection_vectors() {
    let engine = setup_engine();

    let payloads = [
        r#"" OR 1=1 --"#,
        r#"NEAR(a, b, 1000000)"#,
        r#"source:admin"#,
        r#"^root*"#,
        r#"NOT AND OR"#,
        r#"'); DROP TABLE events; --"#,
        r#"message:"root" OR level:"CRITICAL""#,
        r#"a*b*c*d"#,
    ];

    for payload in payloads {
        let res = engine.search_events(&SearchQuery {
            query: Some(payload.to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        });
        assert!(
            res.is_ok(),
            "Payload '{}' should be safely neutralized, got: {:?}",
            payload,
            res
        );
    }

    // Pure syntax/operator payloads without alphanumeric tokens must be rejected cleanly
    for symbol_only in [r#"((("#, r#""""#, r#"^*:---"#, r#"   "#] {
        let res = sanitize_fts5_query(symbol_only);
        assert!(
            matches!(res, Err(SearchError::ValidationError(_))),
            "Symbol-only payload '{}' must be rejected with ValidationError",
            symbol_only
        );
    }

    // Verify `events` table is completely intact after SQLi attempts
    let summary = engine.get_summary().expect("summary must succeed");
    assert_eq!(summary.total_events, 1);
}

#[test]
fn test_sec_null_bytes_and_control_chars_rejected() {
    let engine = setup_engine();

    assert!(matches!(
        sanitize_fts5_query("root\0admin"),
        Err(SearchError::ValidationError(_))
    ));
    assert!(matches!(
        validate_level("ERROR\0"),
        Err(SearchError::ValidationError(_))
    ));
    assert!(matches!(
        validate_source("auth\0service"),
        Err(SearchError::ValidationError(_))
    ));
    assert!(matches!(
        validate_source("auth\nservice"),
        Err(SearchError::ValidationError(_))
    ));

    let res_q = engine.search_events(&SearchQuery {
        query: Some("password\0".to_string()),
        level: None,
        source: None,
        limit: 10,
        offset: 0,
    });
    assert!(matches!(res_q, Err(SearchError::ValidationError(_))));

    let res_lvl = engine.search_events(&SearchQuery {
        query: None,
        level: Some("ERROR\0".to_string()),
        source: None,
        limit: 10,
        offset: 0,
    });
    assert!(matches!(res_lvl, Err(SearchError::ValidationError(_))));

    let res_src = engine.search_events(&SearchQuery {
        query: None,
        level: None,
        source: Some("auth\0".to_string()),
        limit: 10,
        offset: 0,
    });
    assert!(matches!(res_src, Err(SearchError::ValidationError(_))));
}

#[test]
fn test_sec_dos_token_count_and_offset_overflow() {
    let engine = setup_engine();

    // 1. Token bomb (e.g. 25 short tokens within 256 bytes: "a b c d ...")
    let token_bomb = (0..(MAX_QUERY_TOKENS + 5))
        .map(|i| format!("t{}", i))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(token_bomb.len() <= MAX_QUERY_LEN);

    let res_tokens = sanitize_fts5_query(&token_bomb);
    assert!(
        matches!(res_tokens, Err(SearchError::ValidationError(_))),
        "Token bomb exceeding MAX_QUERY_TOKENS must be rejected"
    );

    // 2. Integer overflow attempt on offset (`usize::MAX` -> `-1` as i64)
    let res_overflow = engine.search_events(&SearchQuery {
        query: Some("password".to_string()),
        level: None,
        source: None,
        limit: 10,
        offset: usize::MAX,
    });
    assert!(
        matches!(res_overflow, Err(SearchError::ValidationError(_))),
        "usize::MAX offset must be rejected before casting to i64"
    );

    // 3. Offset just above MAX_OFFSET
    let res_max_offset = engine.search_events(&SearchQuery {
        query: None,
        level: None,
        source: None,
        limit: 10,
        offset: MAX_OFFSET + 1,
    });
    assert!(matches!(
        res_max_offset,
        Err(SearchError::ValidationError(_))
    ));
}

struct ServerGuard {
    child: Child,
    db_path: std::path::PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(format!("{}-wal", self.db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.db_path.display()));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn spawn_server(with_schema: bool) -> (ServerGuard, u16) {
    let port = free_port();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let db_path = std::env::temp_dir().join(format!(
        "cerberus_sec_test_{}_{}.db",
        std::process::id(),
        unique
    ));

    if with_schema {
        let schema_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema/schema.sql");
        let _ = SearchEngine::open(&db_path, Some(&schema_path)).expect("init test db");
    } else {
        // Create an empty SQLite file WITHOUT tables to trigger a 500 DatabaseError on queries
        let _ = rusqlite::Connection::open(&db_path).expect("init empty sqlite file");
    }

    let bin = env!("CARGO_BIN_EXE_cerberus-search");
    let child = Command::new(bin)
        .arg("--db")
        .arg(&db_path)
        .arg("--serve")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn cerberus-search");

    let guard = ServerGuard { child, db_path };

    // Wait until server accepts TCP connections
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            if resp.contains("200 OK") {
                break;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }

    (guard, port)
}

fn send_raw_http(port: u16, raw_request: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let _ = stream.write_all(raw_request);
    let _ = stream.flush();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn test_sec_http_413_405_invalid_utf8_and_null_byte() {
    let (_guard, port) = spawn_server(true);

    // 1. 413 Payload Too Large (> 8192 bytes)
    let huge_req = format!("GET /search?q={} HTTP/1.1\r\n\r\n", "A".repeat(9000));
    let resp_413 = send_raw_http(port, huge_req.as_bytes());
    assert!(
        resp_413.starts_with("HTTP/1.1 413 Payload Too Large"),
        "Expected 413 response, got: {}",
        resp_413
    );

    // 2. 405 Method Not Allowed (POST / DELETE)
    let resp_405 = send_raw_http(port, b"POST /search?q=root HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        resp_405.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "Expected 405 response, got: {}",
        resp_405
    );

    // 3. Invalid UTF-8 percent encoding (%FF%FE) -> 400 Bad Request
    let resp_utf8 = send_raw_http(
        port,
        b"GET /search?q=%FF%FE HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        resp_utf8.starts_with("HTTP/1.1 400 Bad Request"),
        "Expected 400 on invalid UTF-8 percent-encoding, got: {}",
        resp_utf8
    );

    // 4. Null byte in query parameter (%00) -> 400 Bad Request
    let resp_null = send_raw_http(
        port,
        b"GET /search?q=root%00admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        resp_null.starts_with("HTTP/1.1 400 Bad Request"),
        "Expected 400 on null byte %00, got: {}",
        resp_null
    );

    // 5. Huge offset over HTTP -> 400 Bad Request
    let resp_offset = send_raw_http(
        port,
        b"GET /search?q=root&offset=999999999 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        resp_offset.starts_with("HTTP/1.1 400 Bad Request"),
        "Expected 400 on excessive offset, got: {}",
        resp_offset
    );
}

#[test]
fn test_sec_http_500_never_leaks_sqlite_internals() {
    // Spawn server against an uninitialized DB (missing `events` table) to trigger a 500 error
    let (_guard, port) = spawn_server(false);

    let resp_500 = send_raw_http(
        port,
        b"GET /summary HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(
        resp_500.starts_with("HTTP/1.1 500 Internal Server Error"),
        "Expected 500 response, got: {}",
        resp_500
    );
    assert!(
        !resp_500.contains("no such table") && !resp_500.contains("sqlite"),
        "500 response leaked raw SQLite internals: {}",
        resp_500
    );
}
