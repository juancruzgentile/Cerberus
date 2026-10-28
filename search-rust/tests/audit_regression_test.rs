//! Regression tests for the issues reported in the audit of commit fac6998.

use cerberus_search::{SearchEngine, SearchQuery};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../schema/schema.sql")
}

fn temp_db(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("cerberus_audit_{}_{}.db", tag, std::process::id()));
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", p.display(), s));
    }
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_server(db: &PathBuf, port: u16, extra: &[&str]) -> Server {
    let child = Command::new(env!("CARGO_BIN_EXE_cerberus-search"))
        .arg("--db")
        .arg(db)
        .arg("--schema")
        .arg(schema_path())
        .arg("--serve")
        .arg(port.to_string())
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(started.elapsed() < Duration::from_secs(5), "server did not start");
        thread::sleep(Duration::from_millis(20));
    }
    Server(child)
}

fn http_get(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", path).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// A stored row with invalid UTF-8 (legacy data) must not break queries.
#[test]
fn invalid_utf8_rows_do_not_break_search_or_summary() {
    let engine = SearchEngine::open_in_memory(
        &std::fs::read_to_string(schema_path()).expect("schema"),
    )
    .expect("engine");
    engine
        .connection()
        .execute_batch(
            "INSERT INTO events (source, level, message) VALUES
               (CAST(X'6261642DC328' AS TEXT), 'ERROR', CAST(X'6F6B20FF20626164' AS TEXT));",
        )
        .expect("insert raw bytes");

    let resp = engine
        .search_events(&SearchQuery::default())
        .expect("search must not fail on invalid UTF-8");
    assert_eq!(resp.count, 1);
    assert!(resp.results[0].message.contains('\u{FFFD}'));
    engine.get_summary().expect("summary must not fail on invalid UTF-8");
}

/// With umask 022 the database created by the Rust head must be 0600.
#[cfg(unix)]
#[test]
fn new_database_is_private_with_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;
    let db = temp_db("perm");
    let status = Command::new("sh")
        .arg("-c")
        .arg("umask 022; exec \"$0\" --db \"$1\" --schema \"$2\" --summary")
        .arg(env!("CARGO_BIN_EXE_cerberus-search"))
        .arg(&db)
        .arg(schema_path())
        .stdout(Stdio::null())
        .status()
        .expect("run");
    assert!(status.success());
    let mode = std::fs::metadata(&db).expect("db exists").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "database mode is {:o}", mode);
    let _ = std::fs::remove_file(&db);
}

/// An idle client must not delay other requests (was ~5 s before).
#[test]
fn idle_connection_does_not_block_health() {
    let db = temp_db("idle");
    let port = free_port();
    let _srv = start_server(&db, port, &[]);

    let _idle = TcpStream::connect(("127.0.0.1", port)).expect("idle connect");
    thread::sleep(Duration::from_millis(100));

    let t = Instant::now();
    let resp = http_get(port, "/health");
    assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
    assert!(
        t.elapsed() < Duration::from_millis(1000),
        "/health took {:?} with an idle connection open",
        t.elapsed()
    );
}

/// The dashboard must point to the configured ingestor, not a fixed :8080.
#[test]
fn dashboard_uses_configured_ingest_url() {
    let db = temp_db("ui");
    let port = free_port();
    let _srv = start_server(&db, port, &["--ingest-url", "http://127.0.0.1:18080"]);

    let resp = http_get(port, "/");
    assert!(resp.contains("content=\"http://127.0.0.1:18080\""), "ingest URL not injected");
    assert!(!resp.contains("__CERBERUS_INGEST_URL__"));
    assert!(resp.contains("connect-src 'self' http://127.0.0.1:18080;"));
}

#[test]
fn ingest_url_rejects_non_loopback_values() {
    let out = Command::new(env!("CARGO_BIN_EXE_cerberus-search"))
        .args(["--ingest-url", "http://evil.example\"><script>", "--serve", "1"])
        .output()
        .expect("run");
    assert!(!out.status.success());
}
