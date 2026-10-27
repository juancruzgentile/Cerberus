#!/usr/bin/env python3
"""
Cerberus Head 1 (C11 Ingestor) — Security & Resilience Validation Suite
=======================================================================
Audits and stress-tests both the CLI binary and the live HTTP server:
  1. SQL Injection & Format String resilience (prepared statement verification).
  2. Buffer Overflow & Boundary tests (100KB payloads, oversized fields, headers).
  3. SSRF & CRLF Injection prevention on webhook_url (169.254.169.254, 0.0.0.0,
     metadata.google.internal, file://, gopher://, decimal/hex/octal IPs, userinfo @).
  4. HTTP Parser hardening (Content-Length integer overflow, duplicate CL,
     Transfer-Encoding rejection, truncated body, unclosed quotes, \\u0000, deep nesting).
  5. DoS & Socket resilience (empty connections, Slowloris trickle, abrupt TCP RST /
     SIGPIPE immunity) confirming the C11 process never crashes (no SIGSEGV/SIGABRT)
     and continues serving HTTP 200 OK on /health.
"""

import json
import os
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

INGESTOR_DIR = Path(__file__).resolve().parent.parent
INGESTOR_BIN = INGESTOR_DIR / "bin" / "cerberus-ingestor"
SCHEMA_PATH = INGESTOR_DIR.parent / "schema" / "schema.sql"


def send_raw_http(port: int, raw_bytes: bytes, recv_timeout: float = 3.0) -> bytes:
    """Sends raw bytes to 127.0.0.1:port and returns the raw HTTP response."""
    with socket.create_connection(("127.0.0.1", port), timeout=recv_timeout) as sock:
        sock.settimeout(recv_timeout)
        try:
            sock.sendall(raw_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break
            except ConnectionResetError:
                break
        return b"".join(chunks)


class TestCerberusIngestorSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not INGESTOR_BIN.exists():
            raise RuntimeError(f"Binary not found at {INGESTOR_BIN}. Compile first.")
        cls.tmpdir = tempfile.TemporaryDirectory(prefix="cerberus_sec_test_")
        cls.db_path = Path(cls.tmpdir.name) / "sec_test.db"
        cls.port = 18992

        cls.server_proc = subprocess.Popen(
            [
                str(INGESTOR_BIN),
                "--db",
                str(cls.db_path),
                "--schema",
                str(SCHEMA_PATH),
                "--serve",
                str(cls.port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for HTTP server readiness on 127.0.0.1
        deadline = time.monotonic() + 5.0
        ready = False
        while time.monotonic() < deadline:
            if cls.server_proc.poll() is not None:
                stderr_out = cls.server_proc.stderr.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Server exited prematurely: {stderr_out}")
            try:
                resp = send_raw_http(
                    cls.port,
                    b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    recv_timeout=0.5,
                )
                if b"200 OK" in resp:
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)

        if not ready:
            cls.server_proc.kill()
            raise RuntimeError("Timed out waiting for cerberus-ingestor HTTP server")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server_proc") and cls.server_proc.poll() is None:
            cls.server_proc.send_signal(signal.SIGTERM)
            try:
                cls.server_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                cls.server_proc.kill()
        if hasattr(cls, "tmpdir"):
            cls.tmpdir.cleanup()

    def assert_server_alive_and_healthy(self):
        """Verifies the C11 server has not crashed (SIGSEGV/SIGABRT) and answers 200 OK on /health."""
        rc = self.server_proc.poll()
        self.assertIsNone(rc, f"Server process died unexpectedly with exit code {rc}")
        resp = send_raw_http(
            self.port,
            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        self.assertIn(b"HTTP/1.1 200 OK", resp)
        self.assertIn(b'"status":"ok"', resp)

    def post_json_raw(self, body_str: str) -> bytes:
        body_bytes = body_str.encode("utf-8")
        req = (
            f"POST /ingest HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8") + body_bytes
        return send_raw_http(self.port, req)

    # -------------------------------------------------------------------------
    # 1. File Permissions & SQL Injection / Format String Defense
    # -------------------------------------------------------------------------
    def test_01_file_permissions_0600(self):
        mode = stat.S_IMODE(os.stat(self.db_path).st_mode)
        self.assertEqual(mode, 0o600, f"Expected 0600 permissions on DB, got {oct(mode)}")

    def test_02_sql_injection_and_format_strings(self):
        sqli_payloads = [
            "'; DROP TABLE events; DROP TABLE alert_deliveries; --",
            "' OR '1'='1' UNION SELECT sql FROM sqlite_master --",
            "admin'); DELETE FROM events WHERE 1=1; --",
            "%s%s%s%s%s%n%n%n%x%x%p%p",
        ]
        for idx, sqli in enumerate(sqli_payloads):
            payload = json.dumps(
                {
                    "source": f"sqli-src-{idx}",
                    "level": "ERROR",
                    "message": sqli,
                    "metadata": {"injected_sql": sqli, "fmt": "%n%n%s%s"},
                    "webhook_url": "https://127.0.0.1:8443/alerts/hook",
                }
            )
            resp = self.post_json_raw(payload)
            self.assertIn(b"HTTP/1.1 201 Created", resp)

        # Verify tables were not dropped and exact literal strings are stored safely
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events WHERE source LIKE 'sqli-src-%';")
            count = cur.fetchone()[0]
            self.assertEqual(count, len(sqli_payloads))

            cur.execute("SELECT message FROM events WHERE source = 'sqli-src-0';")
            stored_msg = cur.fetchone()[0]
            self.assertEqual(stored_msg, sqli_payloads[0])

        self.assert_server_alive_and_healthy()

    # -------------------------------------------------------------------------
    # 2. SSRF & CRLF Injection Attempts on webhook_url
    # -------------------------------------------------------------------------
    def test_03_ssrf_and_crlf_webhook_rejection(self):
        malicious_webhooks = [
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://169.254.169.254/latest/user-data",
            "http://169.254.170.2/v2/credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://METADATA.GOOGLE.INTERNAL/computeMetadata/v1/",
            "http://metadata.goog/computeMetadata/v1/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            # Wildcard & 0.0.0.0 addresses
            "http://0.0.0.0:8080/admin",
            "https://0.0.0.0/hook",
            "http://0.1.2.3/hook",
            "http://[::]:8080/hook",
            "http://[::0]:8080/hook",
            # Decimal / Hex / Octal IP obfuscations for 169.254.169.254
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://0251.0376.0251.0376/latest/meta-data/",
            # Userinfo '@' credential / host confusion
            "http://safe.example.com@169.254.169.254/latest/",
            "http://user:pass@127.0.0.1:8080/hook",
            # Non-HTTP schemes
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_FLUSHALL",
            "dict://127.0.0.1:11211/stats",
            "ftp://example.com/pub/file",
            # CRLF / header / whitespace injection
            "http://example.com/hook\r\nX-Forwarded-For: 127.0.0.1",
            "http://example.com/hook\nSet-Cookie: evil=1",
            "http://example.com/hook with spaces",
            "http://example.com/hook\twith-tab",
            "http://:8080/missing-host",
            "http:///missing-host",
        ]

        for bad_url in malicious_webhooks:
            payload = json.dumps(
                {
                    "source": "ssrf-tester",
                    "level": "CRITICAL",
                    "message": "Testing webhook validation",
                    "webhook_url": bad_url,
                }
            )
            resp = self.post_json_raw(payload)
            self.assertIn(
                b"HTTP/1.1 400 Bad Request",
                resp,
                f"Malicious webhook URL was not rejected over HTTP: {bad_url!r} -> {resp!r}",
            )

        # Also test via CLI mode (--ingest)
        for bad_url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0:8000/hook",
            "file:///etc/shadow",
            "gopher://127.0.0.1:6379/_INFO",
        ]:
            proc = subprocess.run(
                [
                    str(INGESTOR_BIN),
                    "--db",
                    str(self.db_path),
                    "--ingest",
                    "--source",
                    "cli-ssrf-test",
                    "--level",
                    "CRITICAL",
                    "--message",
                    "CLI SSRF test",
                    "--webhook",
                    bad_url,
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0, f"CLI accepted unsafe webhook: {bad_url}")

        self.assert_server_alive_and_healthy()

    # -------------------------------------------------------------------------
    # 3. 100KB Buffer Overflow Attempts (HTTP & CLI)
    # -------------------------------------------------------------------------
    def test_04_buffer_overflow_100kb_payloads(self):
        # A. 100KB HTTP POST body (> 32KB MAX_HTTP_REQ_SIZE)
        giant_msg = "A" * 102400
        giant_json = (
            '{"source":"overflow-test","level":"INFO","message":"' + giant_msg + '"}'
        )
        resp = self.post_json_raw(giant_json)
        self.assertIn(b"HTTP/1.1 413 Payload Too Large", resp)

        # B. 100KB endless HTTP header without \r\n\r\n
        endless_header = b"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Junk: " + (b"B" * 102400)
        resp_hdr = send_raw_http(self.port, endless_header)
        self.assertIn(b"HTTP/1.1 413 Payload Too Large", resp_hdr)

        # C. Field-level boundary overflows within a <32KB HTTP request
        # source > 128 bytes
        over_source = json.dumps(
            {"source": "S" * 300, "level": "INFO", "message": "valid msg"}
        )
        self.assertIn(b"HTTP/1.1 400 Bad Request", self.post_json_raw(over_source))

        # message > 8192 bytes (e.g., 9000 bytes)
        over_msg = json.dumps(
            {"source": "valid-src", "level": "INFO", "message": "M" * 9000}
        )
        self.assertIn(b"HTTP/1.1 400 Bad Request", self.post_json_raw(over_msg))

        # metadata > 16384 bytes (e.g., 18000 bytes)
        over_meta = json.dumps(
            {
                "source": "valid-src",
                "level": "INFO",
                "message": "valid",
                "metadata": {"pad": "P" * 18000},
            }
        )
        self.assertIn(b"HTTP/1.1 400 Bad Request", self.post_json_raw(over_meta))

        # D. CLI 100KB argument buffer overflow attempt
        proc = subprocess.run(
            [
                str(INGESTOR_BIN),
                "--db",
                str(self.db_path),
                "--ingest",
                "--source",
                "cli-overflow",
                "--level",
                "INFO",
                "--message",
                "X" * 100000,
            ],
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 1, "CLI must reject 100KB message cleanly with exit code 1")
        self.assertGreaterEqual(proc.returncode, 0, "CLI died with a fatal signal (e.g. SIGSEGV)!")

        self.assert_server_alive_and_healthy()

    # -------------------------------------------------------------------------
    # 4. Content-Length Integer Overflows & Malformed / Truncated JSON
    # -------------------------------------------------------------------------
    def test_05_content_length_overflows_and_malformed_json(self):
        # Integer overflow in Content-Length (2^64 - 1 and 2^128)
        for cl_val in ["18446744073709551615", "99999999999999999999999999999999", "65536"]:
            req = (
                f"POST /ingest HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Length: {cl_val}\r\n\r\n"
                f"{{}}"
            ).encode("utf-8")
            resp = send_raw_http(self.port, req)
            self.assertIn(b"HTTP/1.1 413 Payload Too Large", resp)

        # Negative & non-numeric Content-Length, duplicate Content-Length, Transfer-Encoding
        bad_headers = [
            b"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -1\r\n\r\n{}",
            b"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 12abc\r\n\r\n{}",
            b"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ]
        for raw_req in bad_headers:
            resp = send_raw_http(self.port, raw_req)
            self.assertIn(b"HTTP/1.1 400 Bad Request", resp)

        # Malformed JSON & escape attacks
        malformed_jsons = [
            '{"source":"s","level":"INFO","message":"unclosed quote}',
            '{"source":"s","level":"INFO","message":"trailing backslash\\',
            '{"source":"s","level":"INFO","message":"bad unicode \\u12"}',
            '{"source":"s","level":"INFO","message":"null byte \\u0000 injection"}',
            '{"source":"s","level":"INFO","message":"raw\x01control"}',
            '{"source":"s\r\ncrlf","level":"INFO","message":"crlf in source"}',
            '{"source":"s","level":"INFO","message":"deep","metadata":' + ("{" * 50) + ("}" * 50) + "}",
            '{"source":"s","level":"INFO","message":"trailing comma",}',
        ]
        for bad_json in malformed_jsons:
            resp = self.post_json_raw(bad_json)
            self.assertIn(
                b"HTTP/1.1 400 Bad Request",
                resp,
                f"Malformed JSON was not rejected: {bad_json!r}",
            )

        # Valid complex escaped JSON (\, \", \n, \t) must succeed
        valid_escaped = json.dumps(
            {
                "source": "escape-audit",
                "level": "WARN",
                "message": 'Line 1\nLine 2\t"quoted" and \\backslash\\',
                "metadata": {"escaped_key": 'val with "quotes" and \\backslash\\ and } brace'},
            }
        )
        resp_ok = self.post_json_raw(valid_escaped)
        self.assertIn(b"HTTP/1.1 201 Created", resp_ok)

        self.assert_server_alive_and_healthy()

    # -------------------------------------------------------------------------
    # 5. Slow / Empty / Truncated Connections & TCP Reset (SIGPIPE) Resilience
    # -------------------------------------------------------------------------
    def test_06_slow_empty_and_reset_connections_dos(self):
        # A. Empty connection (connect and immediately close without sending data)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2.0) as s:
            pass

        # B. Idle connection (connect, send nothing, wait for server timeout)
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", self.port), timeout=4.0) as s:
            data = s.recv(1024)
            # Server should time out within ~1-2s and return 400 Bad Request or close
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 3.5, "Idle socket was not timed out by SO_RCVTIMEO!")

        # C. Truncated body (Content-Length claims 500 bytes, client sends 20 and closes)
        trunc_req = (
            b"POST /ingest HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 500\r\n\r\n"
            b'{"source":"trunc"'
        )
        resp_trunc = send_raw_http(self.port, trunc_req)
        self.assertIn(b"HTTP/1.1 400 Bad Request", resp_trunc)

        # D. Abrupt TCP RST right after sending request (tests SIGPIPE immunity)
        for _ in range(10):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
            # Enable SO_LINGER with timeout 0 to force TCP RST on close
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            s.close()

        # Verify server survived all DoS / RST attempts and still serves 200 OK on /health
        self.assert_server_alive_and_healthy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
