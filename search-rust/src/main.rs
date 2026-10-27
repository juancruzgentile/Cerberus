//! Cerberus Head 3 — CLI & Secure HTTP Server (`127.0.0.1:<port>`).
//!
//! Endpoints in `--serve <port>` mode:
//! - `GET /health` -> `200 OK` `{"status":"ok","service":"cerberus-search-rust"}`
//! - `GET /search?q=...&level=...&source=...&limit=...&offset=...` -> `200 OK`
//! - `GET /summary` -> `200 OK`

use cerberus_search::{SearchEngine, SearchError, SearchQuery, DEFAULT_LIMIT};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

/// Maximum HTTP request header/line payload in bytes (`<= 8192`).
const MAX_HTTP_REQUEST_BYTES: usize = 8192;
/// Socket read/write timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 5;

#[derive(Debug)]
struct CliConfig {
    db_path: PathBuf,
    schema_path: Option<PathBuf>,
    mode: ExecutionMode,
}

#[derive(Debug)]
enum ExecutionMode {
    Serve {
        port: u16,
    },
    Query {
        query: Option<String>,
        level: Option<String>,
        source: Option<String>,
        limit: usize,
        offset: usize,
    },
    Summary,
}

#[derive(Serialize)]
struct ErrorPayload<'a> {
    error: &'a str,
    message: String,
}

#[derive(Serialize)]
struct HealthPayload<'a> {
    status: &'a str,
    service: &'a str,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{{\"error\":\"{}\"}}", escape_json_str(&err.to_string()));
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = parse_cli_args(&args)?;

    let engine = SearchEngine::open(&config.db_path, config.schema_path.as_deref())
        .map_err(|e| e.to_string())?;

    match config.mode {
        ExecutionMode::Summary => {
            let summary = engine.get_summary().map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
            println!("{}", json);
            Ok(())
        }
        ExecutionMode::Query {
            query,
            level,
            source,
            limit,
            offset,
        } => {
            let response = engine
                .search_events(&SearchQuery {
                    query,
                    level,
                    source,
                    limit,
                    offset,
                })
                .map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&response).map_err(|e| e.to_string())?;
            println!("{}", json);
            Ok(())
        }
        ExecutionMode::Serve { port } => serve_http(
            &config.db_path,
            config.schema_path.as_deref(),
            port,
        ),
    }
}

fn parse_cli_args(args: &[String]) -> Result<CliConfig, String> {
    let mut db_path: Option<PathBuf> = None;
    let mut schema_path: Option<PathBuf> = None;
    let mut serve_port: Option<u16> = None;
    let mut summary_flag = false;
    let mut query: Option<String> = None;
    let mut level: Option<String> = None;
    let mut source: Option<String> = None;
    let mut limit: usize = DEFAULT_LIMIT;
    let mut offset: usize = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --db")?;
                db_path = Some(PathBuf::from(val));
            }
            "--schema" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --schema")?;
                schema_path = Some(PathBuf::from(val));
            }
            "--serve" => {
                i += 1;
                let val = args.get(i).ok_or("Missing port value for --serve")?;
                let port: u16 = val
                    .parse()
                    .map_err(|_| format!("Invalid port number: {}", val))?;
                if port == 0 {
                    return Err("Port cannot be 0".to_string());
                }
                serve_port = Some(port);
            }
            "--summary" => {
                summary_flag = true;
            }
            "--query" | "-q" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --query")?;
                query = Some(val.clone());
            }
            "--level" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --level")?;
                level = Some(val.clone());
            }
            "--source" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --source")?;
                source = Some(val.clone());
            }
            "--limit" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --limit")?;
                limit = val
                    .parse()
                    .map_err(|_| format!("Invalid --limit value: {}", val))?;
            }
            "--offset" => {
                i += 1;
                let val = args.get(i).ok_or("Missing value for --offset")?;
                offset = val
                    .parse()
                    .map_err(|_| format!("Invalid --offset value: {}", val))?;
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
        i += 1;
    }

    let db_path = db_path.unwrap_or_else(|| PathBuf::from("cerberus.db"));

    let mode = if let Some(port) = serve_port {
        ExecutionMode::Serve { port }
    } else if summary_flag {
        ExecutionMode::Summary
    } else if query.is_some() || level.is_some() || source.is_some() {
        ExecutionMode::Query {
            query,
            level,
            source,
            limit,
            offset,
        }
    } else {
        return Err(
            "No action specified. Use --serve <port>, --summary, or --query <q> [--level <lvl>] [--source <src>]"
                .to_string(),
        );
    };

    Ok(CliConfig {
        db_path,
        schema_path,
        mode,
    })
}

fn print_usage() {
    println!(
        "Usage: cerberus-search --db <path> [--schema <path>] [MODE]
Modes:
  --serve <port>                              Start HTTP server on 127.0.0.1:<port>
  --summary                                   Print JSON system summary
  --query <q> [--level <lvl>] [--source <s>]  Run FTS5 search from CLI"
    );
}

fn serve_http(db_path: &Path, schema_path: Option<&Path>, port: u16) -> Result<(), String> {
    // Initialize DB & schema once before accepting connections
    let engine = SearchEngine::open(db_path, schema_path).map_err(|e| e.to_string())?;

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| format!("Failed to bind HTTP server on {}: {}", addr, e))?;

    eprintln!(
        "{{\"status\":\"listening\",\"address\":\"http://{}\",\"service\":\"cerberus-search-rust\"}}",
        addr
    );

    for stream_res in listener.incoming() {
        match stream_res {
            Ok(stream) => {
                if let Err(err) = handle_http_connection(stream, &engine) {
                    eprintln!(
                        "{{\"level\":\"WARN\",\"msg\":\"HTTP connection error: {}\"}}",
                        escape_json_str(&err)
                    );
                }
            }
            Err(err) => {
                eprintln!(
                    "{{\"level\":\"WARN\",\"msg\":\"Accept error: {}\"}}",
                    escape_json_str(&err.to_string())
                );
            }
        }
    }

    Ok(())
}

fn handle_http_connection(mut stream: TcpStream, engine: &SearchEngine) -> Result<(), String> {
    let total_deadline = Duration::from_secs(HTTP_TIMEOUT_SECS);
    let started = Instant::now();
    stream
        .set_read_timeout(Some(total_deadline))
        .map_err(|e| format!("set_read_timeout failed: {}", e))?;
    stream
        .set_write_timeout(Some(total_deadline))
        .map_err(|e| format!("set_write_timeout failed: {}", e))?;

    let mut buffer = [0_u8; MAX_HTTP_REQUEST_BYTES + 1];
    let mut total_read = 0usize;

    loop {
        let elapsed = started.elapsed();
        if elapsed >= total_deadline {
            return Err("HTTP request timed out (total deadline exceeded)".to_string());
        }
        let remaining = total_deadline.saturating_sub(elapsed);
        let _ = stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))));

        if total_read >= buffer.len() {
            send_json_response(
                &mut stream,
                413,
                "Payload Too Large",
                &serde_json::to_string(&ErrorPayload {
                    error: "payload_too_large",
                    message: format!(
                        "Request exceeds maximum size of {} bytes",
                        MAX_HTTP_REQUEST_BYTES
                    ),
                })
                .unwrap_or_else(|_| "{\"error\":\"payload_too_large\"}".to_string()),
            )?;
            return Ok(());
        }

        match stream.read(&mut buffer[total_read..]) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if buffer[..total_read].windows(4).any(|w| w == b"\r\n\r\n")
                    || buffer[..total_read].windows(2).any(|w| w == b"\n\n")
                {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("Socket read error: {}", e)),
        }
    }

    if total_read == 0 {
        return Ok(());
    }

    if total_read > MAX_HTTP_REQUEST_BYTES {
        send_json_response(
            &mut stream,
            413,
            "Payload Too Large",
            r#"{"error":"payload_too_large","message":"Request exceeds 8192 bytes"}"#,
        )?;
        return Ok(());
    }

    let req_str = match std::str::from_utf8(&buffer[..total_read]) {
        Ok(s) => s,
        Err(_) => {
            send_json_response(
                &mut stream,
                400,
                "Bad Request",
                r#"{"error":"bad_request","message":"Request is not valid UTF-8"}"#,
            )?;
            return Ok(());
        }
    };

    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");

    if method.is_empty() || raw_target.is_empty() {
        send_json_response(
            &mut stream,
            400,
            "Bad Request",
            r#"{"error":"bad_request","message":"Malformed HTTP request line"}"#,
        )?;
        return Ok(());
    }

    if method != "GET" {
        send_json_response(
            &mut stream,
            405,
            "Method Not Allowed",
            r#"{"error":"method_not_allowed","message":"Only GET method is supported"}"#,
        )?;
        return Ok(());
    }

    let (path, query_str) = match raw_target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw_target, None),
    };

    match path {
        "/health" => {
            let body = serde_json::to_string(&HealthPayload {
                status: "ok",
                service: "cerberus-search-rust",
            })
            .unwrap_or_else(|_| r#"{"status":"ok","service":"cerberus-search-rust"}"#.to_string());
            send_json_response(&mut stream, 200, "OK", &body)?;
        }
        "/summary" => match engine.get_summary() {
            Ok(summary) => {
                let body = serde_json::to_string(&summary).map_err(|e| e.to_string())?;
                send_json_response(&mut stream, 200, "OK", &body)?;
            }
            Err(err) => {
                send_search_error(&mut stream, err)?;
            }
        },
        "/search" => {
            let params_map = match parse_query_string(query_str.unwrap_or("")) {
                Ok(m) => m,
                Err(msg) => {
                    let body = serde_json::to_string(&ErrorPayload {
                        error: "bad_request",
                        message: msg,
                    })
                    .unwrap_or_else(|_| r#"{"error":"bad_request"}"#.to_string());
                    send_json_response(&mut stream, 400, "Bad Request", &body)?;
                    return Ok(());
                }
            };

            let query = params_map
                .get("q")
                .or_else(|| params_map.get("query"))
                .cloned();
            let level = params_map.get("level").cloned();
            let source = params_map.get("source").cloned();

            let limit = match params_map.get("limit") {
                Some(v) => match v.parse::<usize>() {
                    Ok(n) if n >= 1 => n,
                    _ => {
                        let body = serde_json::to_string(&ErrorPayload {
                            error: "validation_error",
                            message: "Parameter 'limit' must be a positive integer".to_string(),
                        })
                        .unwrap_or_else(|_| r#"{"error":"validation_error"}"#.to_string());
                        send_json_response(&mut stream, 400, "Bad Request", &body)?;
                        return Ok(());
                    }
                },
                None => DEFAULT_LIMIT,
            };

            let offset = match params_map.get("offset") {
                Some(v) => match v.parse::<usize>() {
                    Ok(n) => n,
                    Err(_) => {
                        let body = serde_json::to_string(&ErrorPayload {
                            error: "validation_error",
                            message: "Parameter 'offset' must be a non-negative integer"
                                .to_string(),
                        })
                        .unwrap_or_else(|_| r#"{"error":"validation_error"}"#.to_string());
                        send_json_response(&mut stream, 400, "Bad Request", &body)?;
                        return Ok(());
                    }
                },
                None => 0,
            };

            let search_query = SearchQuery {
                query,
                level,
                source,
                limit,
                offset,
            };

            match engine.search_events(&search_query) {
                Ok(resp) => {
                    let body = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
                    send_json_response(&mut stream, 200, "OK", &body)?;
                }
                Err(err) => {
                    send_search_error(&mut stream, err)?;
                }
            }
        }
        _ => {
            send_json_response(
                &mut stream,
                404,
                "Not Found",
                r#"{"error":"not_found","message":"Endpoint not found"}"#,
            )?;
        }
    }

    Ok(())
}

fn send_search_error(stream: &mut TcpStream, err: SearchError) -> Result<(), String> {
    let (status_code, status_text, err_code, public_msg) = match err {
        SearchError::ValidationError(_) => (400, "Bad Request", "validation_error", err.to_string()),
        SearchError::DatabaseError(_)
        | SearchError::IoError(_)
        | SearchError::SerializationError(_) => {
            eprintln!(
                "{{\"level\":\"ERROR\",\"msg\":\"Internal search error: {}\"}}",
                escape_json_str(&err.to_string())
            );
            (
                500,
                "Internal Server Error",
                "internal_error",
                "Internal server error".to_string(),
            )
        }
    };

    let body = serde_json::to_string(&ErrorPayload {
        error: err_code,
        message: public_msg,
    })
    .unwrap_or_else(|_| r#"{"error":"internal_error"}"#.to_string());

    send_json_response(stream, status_code, status_text, &body)
}

fn send_json_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    json_body: &str,
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status_code,
        status_text,
        json_body.len(),
        json_body
    );

    stream
        .write_all(response.as_bytes())
        .map_err(|e| format!("Socket write error: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("Socket flush error: {}", e))?;
    Ok(())
}

/// Safely decodes a URL query string (`key=value&...`) with percent-decoding.
pub fn parse_query_string(raw: &str) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    if raw.trim().is_empty() {
        return Ok(map);
    }

    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let decoded_key = percent_decode(k)?;
        let decoded_val = percent_decode(v)?;
        map.insert(decoded_key, decoded_val);
    }

    Ok(map)
}

/// Decodes percent-encoded UTF-8 sequences (`%XX`) and `+` as space.
pub fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err("Incomplete percent-encoding sequence".to_string());
                }
                let hi = from_hex_digit(bytes[i + 1])?;
                let lo = from_hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    let decoded = String::from_utf8(out)
        .map_err(|_| "Decoded query parameter is not valid UTF-8".to_string())?;
    if decoded.contains('\0') {
        return Err("Decoded query parameter contains invalid null byte".to_string());
    }
    Ok(decoded)
}

fn from_hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("Invalid hex digit in percent-encoding: {}", b as char)),
    }
}

fn escape_json_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_decode_and_query_string() {
        let qs = "q=failed+password%20root%2A&level=ERROR&limit=25";
        let parsed = parse_query_string(qs).unwrap_or_default();
        assert_eq!(
            parsed.get("q").map(String::as_str),
            Some("failed password root*")
        );
        assert_eq!(parsed.get("level").map(String::as_str), Some("ERROR"));
        assert_eq!(parsed.get("limit").map(String::as_str), Some("25"));
    }

    #[test]
    fn test_percent_decode_rejects_malformed_hex() {
        assert!(percent_decode("bad%2").is_err());
        assert!(percent_decode("bad%ZZ").is_err());
    }
}
