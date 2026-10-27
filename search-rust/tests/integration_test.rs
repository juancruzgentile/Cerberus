use cerberus_search::{
     sanitize_fts5_query, SearchEngine, SearchError, SearchQuery, SystemSummary, SearchResponse,
    MAX_LIMIT, MAX_OFFSET, MAX_QUERY_LEN, MAX_SOURCE_LEN,
};
use rusqlite::params;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SCHEMA_SQL: &str = include_str!("../../schema/schema.sql");

fn insert_event(
    engine: &SearchEngine,
    source: &str,
    level: &str,
    message: &str,
    metadata_json: &str,
    created_at: i64,
) -> i64 {
    let conn = engine.connection();
    conn.execute(
        "INSERT INTO events (source, level, message, metadata_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![source, level, message, metadata_json, created_at],
    )
    .expect("Failed to insert test event");
    conn.last_insert_rowid()
}

fn insert_alert(
    engine: &SearchEngine,
    event_id: i64,
    target_url: &str,
    status: &str,
    attempts: i64,
    max_attempts: i64,
) {
    let conn = engine.connection();
    conn.execute(
        "INSERT INTO alert_deliveries (event_id, target_url, status, attempts, max_attempts)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![event_id, target_url, status, attempts, max_attempts],
    )
    .expect("Failed to insert test alert delivery");
}

#[test]
fn test_fts5_indexing_bm25_relevance_and_snippets() {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("open_in_memory failed");

    // Event 1: mentions "database" and "deadlock" once in a longer message
    let id_low_density = insert_event(
        &engine,
        "order-service",
        "WARN",
        "Background worker noticed a transient database lock contention and possible deadlock during nightly cleanup job",
        r#"{"job":"cleanup"}"#,
        1700000100,
    );

    // Event 2: mentions "deadlock" and "database" multiple times (higher BM25 relevance)
    let id_high_density = insert_event(
        &engine,
        "db-proxy",
        "CRITICAL",
        "Critical database deadlock detected: database transaction aborted due to deadlock on primary shard",
        r#"{"shard":"primary"}"#,
        1700000200,
    );

    // Event 3: unrelated event
    insert_event(
        &engine,
        "auth-service",
        "INFO",
        "User login succeeded via OAuth2 provider",
        r#"{"provider":"github"}"#,
        1700000300,
    );

    let resp = engine
        .search_events(&SearchQuery {
            query: Some("database deadlock".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect("search_events failed");

    assert_eq!(resp.count, 2);
    assert_eq!(resp.total_matches, 2);
    assert_eq!(
        resp.sanitized_query.as_deref(),
        Some("\"database\" \"deadlock\"")
    );

    // Verify BM25 ordering: in SQLite FTS5, more relevant rows have smaller (more negative) bm25() values
    let first = &resp.results[0];
    let second = &resp.results[1];
    assert_eq!(first.id, id_high_density);
    assert_eq!(second.id, id_low_density);
    assert!(
        first.rank < second.rank,
        "Expected first.rank ({}) < second.rank ({})",
        first.rank,
        second.rank
    );
    assert!(first.rank < 0.0);

    // Verify snippet highlighting uses '[' and ']' markers around matched terms
    assert!(
        first.snippet.contains("[database]") || first.snippet.contains("[deadlock]"),
        "Snippet did not contain highlighted term: {}",
        first.snippet
    );
    assert!(
        second.snippet.contains("[database]") || second.snippet.contains("[deadlock]"),
        "Snippet did not contain highlighted term: {}",
        second.snippet
    );

    // Verify FTS5 triggers on UPDATE and DELETE
    engine
        .connection()
        .execute(
            "UPDATE events SET message = 'Resolved connection issue cleanly' WHERE id = ?1",
            params![id_low_density],
        )
        .expect("UPDATE event failed");

    let after_update = engine
        .search_events(&SearchQuery {
            query: Some("deadlock".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect("search after update failed");
    assert_eq!(after_update.total_matches, 1);
    assert_eq!(after_update.results[0].id, id_high_density);

    engine
        .connection()
        .execute("DELETE FROM events WHERE id = ?1", params![id_high_density])
        .expect("DELETE event failed");

    let after_delete = engine
        .search_events(&SearchQuery {
            query: Some("deadlock".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect("search after delete failed");
    assert_eq!(after_delete.total_matches, 0);
    assert!(after_delete.results.is_empty());
}

#[test]
fn test_fts5_prefix_search_timeout_wildcard() {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("open_in_memory failed");

    let id1 = insert_event(
        &engine,
        "api-gateway",
        "ERROR",
        "Upstream service experienced multiple read timeouts while awaiting response",
        r#"{"upstream":"billing"}"#,
        1700001001,
    );

    let id2 = insert_event(
        &engine,
        "payment-worker",
        "CRITICAL",
        "Fatal timeout_error raised by TLS handshake on gateway socket",
        r#"{"code":"E_TIMEOUT"}"#,
        1700001002,
    );

    insert_event(
        &engine,
        "scheduler",
        "DEBUG",
        "Cron timer tick executed on schedule",
        r#"{}"#,
        1700001003,
    );

    let resp = engine
        .search_events(&SearchQuery {
            query: Some("timeout*".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect("prefix search failed");

    assert_eq!(resp.sanitized_query.as_deref(), Some("\"timeout\"*"));
    assert_eq!(resp.total_matches, 2);
    assert_eq!(resp.count, 2);

    let matched_ids: Vec<i64> = resp.results.iter().map(|r| r.id).collect();
    assert!(matched_ids.contains(&id1));
    assert!(matched_ids.contains(&id2));

    for item in &resp.results {
        assert!(
            item.snippet.contains("[timeouts]")
                || item.snippet.contains("[timeout]_error")
                || item.snippet.contains("[timeout_error]"),
            "Expected prefix highlight in snippet, got: {}",
            item.snippet
        );
    }

    // Verify that exact search "timeout" (without '*') only matches "timeout_error" (where 'timeout' is a token)
    // and does NOT match plural "timeouts", proving prefix wildcard expansion is active.
    let exact_resp = engine
        .search_events(&SearchQuery {
            query: Some("timeout".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect("exact search failed");
    assert_eq!(exact_resp.total_matches, 1);
    assert_eq!(exact_resp.results[0].id, id2);
}

#[test]
fn test_combined_filters_and_pagination_total_matches() {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("open_in_memory failed");

    // Seed 7 matching events for (query="timeout*", level="ERROR", source="api-gateway")
    for i in 1..=7 {
        insert_event(
            &engine,
            "api-gateway",
            "ERROR",
            &format!("Gateway request timeout_error on route /v1/pay attempt {}", i),
            r#"{"route":"/v1/pay"}"#,
            1700002000 + i,
        );
    }

    // Seed events with different level or different source that also contain "timeout_error"
    insert_event(
        &engine,
        "api-gateway",
        "WARN",
        "Soft timeout_error warning on route /v1/health",
        r#"{}"#,
        1700002100,
    );
    insert_event(
        &engine,
        "auth-service",
        "ERROR",
        "LDAP connection timeout_error during bind",
        r#"{}"#,
        1700002101,
    );

    // Seed additional non-timeout events for (level="ERROR", source="api-gateway")
    insert_event(
        &engine,
        "api-gateway",
        "ERROR",
        "Malformed authorization header received",
        r#"{}"#,
        1700002200,
    );

    // 1. Combined: query + level + source with pagination (page 1: limit=3, offset=0)
    let page1 = engine
        .search_events(&SearchQuery {
            query: Some("timeout*".to_string()),
            level: Some("error".to_string()), // lowercase to verify normalization
            source: Some("api-gateway".to_string()),
            limit: 3,
            offset: 0,
        })
        .expect("page1 search failed");

    assert_eq!(page1.level.as_deref(), Some("ERROR"));
    assert_eq!(page1.source.as_deref(), Some("api-gateway"));
    assert_eq!(page1.limit, 3);
    assert_eq!(page1.offset, 0);
    assert_eq!(page1.count, 3);
    assert_eq!(page1.total_matches, 7);

    // Page 2: limit=3, offset=3
    let page2 = engine
        .search_events(&SearchQuery {
            query: Some("timeout*".to_string()),
            level: Some("ERROR".to_string()),
            source: Some("api-gateway".to_string()),
            limit: 3,
            offset: 3,
        })
        .expect("page2 search failed");

    assert_eq!(page2.count, 3);
    assert_eq!(page2.total_matches, 7);

    // Page 3: limit=3, offset=6 -> only 1 remaining result
    let page3 = engine
        .search_events(&SearchQuery {
            query: Some("timeout*".to_string()),
            level: Some("ERROR".to_string()),
            source: Some("api-gateway".to_string()),
            limit: 3,
            offset: 6,
        })
        .expect("page3 search failed");

    assert_eq!(page3.count, 1);
    assert_eq!(page3.total_matches, 7);

    // Ensure all 7 returned IDs across the 3 pages are unique
    let mut all_ids = Vec::new();
    all_ids.extend(page1.results.iter().map(|r| r.id));
    all_ids.extend(page2.results.iter().map(|r| r.id));
    all_ids.extend(page3.results.iter().map(|r| r.id));
    all_ids.sort_unstable();
    all_ids.dedup();
    assert_eq!(all_ids.len(), 7);

    // 2. Filter by level + source ONLY (without query)
    // Should match the 7 timeout ERRORs + 1 Malformed header ERROR = 8 total_matches
    let no_query_page = engine
        .search_events(&SearchQuery {
            query: None,
            level: Some("ERROR".to_string()),
            source: Some("api-gateway".to_string()),
            limit: 5,
            offset: 0,
        })
        .expect("level + source without query failed");

    assert!(no_query_page.sanitized_query.is_none());
    assert_eq!(no_query_page.count, 5);
    assert_eq!(no_query_page.total_matches, 8);
    // Ordered by created_at DESC, so the newest (1700002200) is first and rank is 0.0
    assert_eq!(no_query_page.results[0].created_at, 1700002200);
    assert_eq!(no_query_page.results[0].rank, 0.0);
}

#[test]
fn test_edge_cases_and_validation_errors() {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("open_in_memory failed");

    // 1. limit = 0 rejected with ValidationError
    let err_limit_zero = engine
        .search_events(&SearchQuery {
            query: Some("test".to_string()),
            level: None,
            source: None,
            limit: 0,
            offset: 0,
        })
        .expect_err("limit = 0 must fail");
    assert!(matches!(err_limit_zero, SearchError::ValidationError(_)));

    // 2. limit = 500 (> MAX_LIMIT = 100) rejected with ValidationError
    let err_limit_high = engine
        .search_events(&SearchQuery {
            query: Some("test".to_string()),
            level: None,
            source: None,
            limit: 500,
            offset: 0,
        })
        .expect_err("limit = 500 must fail");
    assert!(matches!(
        err_limit_high,
        SearchError::ValidationError(_)
    ));

    // Boundary check: limit = MAX_LIMIT (100) is accepted
    let ok_max_limit = engine
        .search_events(&SearchQuery {
            query: None,
            level: None,
            source: None,
            limit: MAX_LIMIT,
            offset: 0,
        })
        .expect("limit = MAX_LIMIT should succeed");
    assert_eq!(ok_max_limit.limit, MAX_LIMIT);

    // 3. Invalid level ("TRACE") rejected with ValidationError
    let err_level = engine
        .search_events(&SearchQuery {
            query: None,
            level: Some("TRACE".to_string()),
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect_err("Invalid level TRACE must fail");
    assert!(matches!(err_level, SearchError::ValidationError(_)));

    // 4. Query > 256 bytes rejected with ValidationError
    let long_query = "x".repeat(MAX_QUERY_LEN + 1);
    let err_long_query = engine
        .search_events(&SearchQuery {
            query: Some(long_query),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        })
        .expect_err("Query > 256 bytes must fail");
    assert!(matches!(err_long_query, SearchError::ValidationError(_)));

    // 5. Additional edge cases: empty query, symbol-only query, excessive offset, invalid source
    assert!(matches!(
        engine.search_events(&SearchQuery {
            query: Some("   ".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        }),
        Err(SearchError::ValidationError(_))
    ));

    assert!(matches!(
        engine.search_events(&SearchQuery {
            query: Some("\"*()^:---".to_string()),
            level: None,
            source: None,
            limit: 10,
            offset: 0,
        }),
        Err(SearchError::ValidationError(_))
    ));

    assert!(matches!(
        engine.search_events(&SearchQuery {
            query: None,
            level: None,
            source: Some("s".repeat(MAX_SOURCE_LEN + 1)),
            limit: 10,
            offset: 0,
        }),
        Err(SearchError::ValidationError(_))
    ));

    assert!(matches!(
        engine.search_events(&SearchQuery {
            query: None,
            level: None,
            source: None,
            limit: 10,
            offset: MAX_OFFSET + 1,
        }),
        Err(SearchError::ValidationError(_))
    ));

    // Verify FTS5 operator injection is neutralized into quoted tokens
    let injected = sanitize_fts5_query(r#"admin" OR NEAR(a,b) NOT level:CRITICAL ^9"#)
        .expect("sanitize_fts5_query should neutralize operators");
    assert_eq!(
        injected,
        r#""admin" "OR" "NEAR" "a" "b" "NOT" "level" "CRITICAL" "9""#
    );
}

#[test]
fn test_get_summary_exact_counts_and_ordering() {
    let engine = SearchEngine::open_in_memory(SCHEMA_SQL).expect("open_in_memory failed");

    // Seed exact counts per level:
    // DEBUG: 2, INFO: 4, WARN: 3, ERROR: 5, CRITICAL: 1 (total = 15)
    // Sources:
    // - "ingestor-edge": 6 events
    // - "auth-service": 5 events
    // - "billing-api": 3 events
    // - "audit-log": 1 event
    let seed_plan = [
        ("ingestor-edge", "DEBUG", 2),
        ("ingestor-edge", "INFO", 4),
        ("auth-service", "ERROR", 5),
        ("billing-api", "WARN", 3),
        ("audit-log", "CRITICAL", 1),
    ];

    let mut last_event_id = 0;
    let mut ts = 1700005000_i64;
    for (src, lvl, count) in seed_plan {
        for idx in 0..count {
            ts += 1;
            last_event_id = insert_event(
                &engine,
                src,
                lvl,
                &format!("Event {} from {} with level {}", idx, src, lvl),
                r#"{"seeded":true}"#,
                ts,
            );
        }
    }

    // Seed alert_deliveries:
    // PENDING: 3, SENT: 4, FAILED: 2, DEAD: 1 (total = 10)
    let alert_plan = [
        ("PENDING", 3),
        ("SENT", 4),
        ("FAILED", 2),
        ("DEAD", 1),
    ];
    for (status, count) in alert_plan {
        for _ in 0..count {
            insert_alert(
                &engine,
                last_event_id,
                "https://alerts.example.com/webhook",
                status,
                1,
                3,
            );
        }
    }

    let summary = engine.get_summary().expect("get_summary failed");

    assert_eq!(summary.total_events, 15);
    assert_eq!(summary.events_by_level.debug, 2);
    assert_eq!(summary.events_by_level.info, 4);
    assert_eq!(summary.events_by_level.warn, 3);
    assert_eq!(summary.events_by_level.error, 5);
    assert_eq!(summary.events_by_level.critical, 1);

    assert_eq!(summary.top_sources.len(), 4);
    assert_eq!(summary.top_sources[0].source, "ingestor-edge");
    assert_eq!(summary.top_sources[0].count, 6);
    assert_eq!(summary.top_sources[1].source, "auth-service");
    assert_eq!(summary.top_sources[1].count, 5);
    assert_eq!(summary.top_sources[2].source, "billing-api");
    assert_eq!(summary.top_sources[2].count, 3);
    assert_eq!(summary.top_sources[3].source, "audit-log");
    assert_eq!(summary.top_sources[3].count, 1);

    assert_eq!(summary.alerts.pending, 3);
    assert_eq!(summary.alerts.sent, 4);
    assert_eq!(summary.alerts.failed, 2);
    assert_eq!(summary.alerts.dead, 1);
    assert_eq!(summary.alerts.total, 10);
}

struct ServerProcessGuard {
    child: Child,
    db_path: PathBuf,
}

impl Drop for ServerProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(format!("{}-wal", self.db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.db_path.display()));
    }
}

fn send_raw_http_get(port: u16, request_line: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("Failed to connect to server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set_read_timeout failed");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set_write_timeout failed");

    let req = format!(
        "{}\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        request_line, port
    );
    stream
        .write_all(req.as_bytes())
        .expect("Failed to write HTTP request");
    stream.flush().expect("Failed to flush HTTP request");

    let mut raw_resp = String::new();
    stream
        .read_to_string(&mut raw_resp)
        .expect("Failed to read HTTP response");

    let (headers, body) = raw_resp
        .split_once("\r\n\r\n")
        .expect("Malformed HTTP response");
    let status_line = headers.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    (status_code, headers.to_string(), body.to_string())
}

#[test]
fn test_http_server_loopback_endpoints() {
    // Allocate a free ephemeral port on loopback
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
        listener.local_addr().unwrap().port()
    };

    let mut db_path = std::env::temp_dir();
    db_path.push(format!(
        "cerberus_search_http_test_{}_{}.db",
        std::process::id(),
        port
    ));
    let _ = std::fs::remove_file(&db_path);

    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../schema/schema.sql");

    // Seed the SQLite database on disk before starting the HTTP server
    {
        let engine = SearchEngine::open(&db_path, Some(&schema_path))
            .expect("Failed to open & initialize disk DB");
        let ev1 = insert_event(
            &engine,
            "api-gateway",
            "ERROR",
            "Upstream connection timeout_error while forwarding payload",
            r#"{"upstream":"auth"}"#,
            1700010001,
        );
        insert_event(
            &engine,
            "api-gateway",
            "WARN",
            "Slow response timeouts observed on edge node",
            r#"{"node":"edge-1"}"#,
            1700010002,
        );
        insert_event(
            &engine,
            "db-node",
            "CRITICAL",
            "Disk quota exceeded on replica volume",
            r#"{"volume":"sda1"}"#,
            1700010003,
        );
        insert_alert(
            &engine,
            ev1,
            "https://hooks.example.org/cerberus",
            "SENT",
            1,
            3,
        );
    }

    let bin_path = env!("CARGO_BIN_EXE_cerberus-search");
    let child = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--schema")
        .arg(&schema_path)
        .arg("--serve")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn cerberus-search HTTP server");

    let _guard = ServerProcessGuard { child, db_path };

    // Wait until the loopback port is accepting connections
    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(5) {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(ready, "HTTP server did not start listening within 5s");

    // 1. GET /health
    let (status, headers, body) = send_raw_http_get(port, "GET /health HTTP/1.1");
    assert_eq!(status, 200);
    assert!(headers.contains("Content-Type: application/json; charset=utf-8"));
    assert!(headers.contains("X-Content-Type-Options: nosniff"));
    let health_json: serde_json::Value =
        serde_json::from_str(&body).expect("Invalid JSON from /health");
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["service"], "cerberus-search-rust");

    // 2. GET /search?q=timeout*&source=api-gateway&limit=10&offset=0
    let (status, _headers, body) = send_raw_http_get(
        port,
        "GET /search?q=timeout%2A&source=api-gateway&limit=10&offset=0 HTTP/1.1",
    );
    assert_eq!(status, 200);
    let search_resp: SearchResponse =
        serde_json::from_str(&body).expect("Invalid SearchResponse JSON from /search");
    assert_eq!(search_resp.total_matches, 2);
    assert_eq!(search_resp.count, 2);
    assert_eq!(search_resp.source.as_deref(), Some("api-gateway"));
    assert!(
        search_resp.results[0].snippet.contains("[timeout_error]")
            || search_resp.results[0].snippet.contains("[timeout]_error")
            || search_resp.results[0].snippet.contains("[timeouts]")
    );

    // 3. GET /summary
    let (status, _headers, body) = send_raw_http_get(port, "GET /summary HTTP/1.1");
    assert_eq!(status, 200);
    let summary_resp: SystemSummary =
        serde_json::from_str(&body).expect("Invalid SystemSummary JSON from /summary");
    assert_eq!(summary_resp.total_events, 3);
    assert_eq!(summary_resp.events_by_level.error, 1);
    assert_eq!(summary_resp.events_by_level.warn, 1);
    assert_eq!(summary_resp.events_by_level.critical, 1);
    assert_eq!(summary_resp.top_sources[0].source, "api-gateway");
    assert_eq!(summary_resp.top_sources[0].count, 2);
    assert_eq!(summary_resp.alerts.total, 1);
    assert_eq!(summary_resp.alerts.sent, 1);

    // 4. Validation error over HTTP: limit=0 and limit=500 and level=TRACE -> 400 Bad Request
    let (status_zero, _, _) = send_raw_http_get(port, "GET /search?q=timeout&limit=0 HTTP/1.1");
    assert_eq!(status_zero, 400);

    let (status_500, _, _) = send_raw_http_get(port, "GET /search?q=timeout&limit=500 HTTP/1.1");
    assert_eq!(status_500, 400);

    let (status_trace, _, _) = send_raw_http_get(port, "GET /search?level=TRACE HTTP/1.1");
    assert_eq!(status_trace, 400);

    // 5. Method Not Allowed (POST) -> 405
    let (status_post, _, _) = send_raw_http_get(port, "POST /health HTTP/1.1");
    assert_eq!(status_post, 405);
}
