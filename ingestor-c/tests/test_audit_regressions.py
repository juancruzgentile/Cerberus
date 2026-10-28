#!/usr/bin/env python3
"""
Cerberus Head 1 — regression tests for the audit of commit fac6998.

Each test reproduces one reported failure against the live HTTP server:
  - invalid UTF-8 accepted (201) and later breaking the Rust reader
  - \\uXXXX escapes (incl. surrogate pairs) stored as '?'
  - syntactically invalid JSON in ignored fields accepted
  - no CORS preflight for the dashboard / cross-site writes allowed
  - one idle connection blocking every other request
  - database created with 0644 under umask 022
  - SIGTERM with workers stuck on a locked DB: slow exit (~10 s, code 1)
    and SQLite closed while workers could still be using it
"""

import json
import os
import signal
import threading
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

INGESTOR_DIR = Path(__file__).resolve().parent.parent
INGESTOR_BIN = INGESTOR_DIR / "bin" / "cerberus-ingestor"
SCHEMA_PATH = INGESTOR_DIR.parent / "schema" / "schema.sql"
PORT = 18993
ALLOWED_ORIGIN = "http://127.0.0.1:18081"


def raw_http(raw: bytes, timeout: float = 3.0) -> bytes:
    with socket.create_connection(("127.0.0.1", PORT), timeout=timeout) as s:
        s.sendall(raw)
        out = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out


def post(body: bytes, extra_headers: str = "", content_type: str = "application/json") -> bytes:
    ct = f"Content-Type: {content_type}\r\n" if content_type else ""
    head = (
        "POST /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"{ct}{extra_headers}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    )
    return raw_http(head.encode() + body)


def status_of(resp: bytes) -> int:
    return int(resp.split(b" ", 2)[1])


class TestAuditRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="cerberus_audit_")
        cls.db = Path(cls.tmp.name) / "audit.db"
        # umask 022 on purpose: the file must still end up 0600
        cls.proc = subprocess.Popen(
            ["sh", "-c", 'umask 022; exec "$@"', "sh", str(INGESTOR_BIN),
             "--db", str(cls.db), "--schema", str(SCHEMA_PATH),
             "--serve", str(PORT), "--cors-origin", ALLOWED_ORIGIN],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if b"200 OK" in raw_http(b"GET /health HTTP/1.1\r\n\r\n"):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("ingestor did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        cls.tmp.cleanup()

    def stored_message(self, event_id: int) -> str:
        with sqlite3.connect(self.db) as c:
            return c.execute("SELECT message FROM events WHERE id=?", (event_id,)).fetchone()[0]

    def test_invalid_utf8_rejected(self):
        for bad in (b"\xff", b"\xc3\x28", b"\xed\xa0\x80", b"\xc0\xaf", b"\xf4\x90\x80\x80"):
            body = b'{"source":"s","level":"INFO","message":"x' + bad + b'"}'
            self.assertEqual(status_of(post(body)), 400, bad)
        bad_meta = b'{"source":"s","level":"INFO","message":"m","metadata":{"k":"\xff"}}'
        self.assertEqual(status_of(post(bad_meta)), 400)

    def test_unicode_escapes_round_trip(self):
        text = "Español: café 日本 😀"
        for body in (json.dumps({"source": "s", "level": "INFO", "message": text}),  # \\u escapes
                     json.dumps({"source": "s", "level": "INFO", "message": text}, ensure_ascii=False)):
            resp = post(body.encode("utf-8"))
            self.assertEqual(status_of(resp), 201, resp)
            event_id = json.loads(resp.split(b"\r\n\r\n", 1)[1])["event_id"]
            self.assertEqual(self.stored_message(event_id), text)
        # lone / reversed surrogates are invalid
        for esc in ("\\ud83d", "\\ude00", "\\ude00\\ud83d"):
            body = '{"source":"s","level":"INFO","message":"a' + esc + '"}'
            self.assertEqual(status_of(post(body.encode())), 400, esc)

    def test_whole_document_is_validated(self):
        bad_docs = [
            '{"source":"s","level":"INFO","message":"m","unused":notJSON}',
            '{"source":"s","level":"INFO","message":"m","unused":[1,]}',
            '{"source":"s","level":"INFO","message":"m","unused":01}',
            '{"source":"s","level":"INFO","message":"m","unused":{"a" 1}}',
            '{"source":"s","level":"INFO","message":"m","unused":tru}',
            '{"source":"s","level":"INFO","message":"m","metadata":"not an object"}',
            '{"source":"s","source":"t","level":"INFO","message":"m"}',
        ]
        for doc in bad_docs:
            self.assertEqual(status_of(post(doc.encode())), 400, doc)
        ok = '{"source":"s","level":"INFO","message":"m","unused":{"a":[1,-2.5e3,true,null,"x"]}}'
        self.assertEqual(status_of(post(ok.encode())), 201)

    def test_nul_byte_in_body_rejected(self):
        body = b'{"source":"s","level":"INFO","message":"m"}\x00garbage'
        self.assertEqual(status_of(post(body)), 400)

    def test_cors_preflight_and_origin_policy(self):
        pre = raw_http(
            ("OPTIONS /ingest HTTP/1.1\r\nHost: 127.0.0.1\r\n"
             f"Origin: {ALLOWED_ORIGIN}\r\nAccess-Control-Request-Method: POST\r\n"
             "Access-Control-Request-Headers: content-type\r\n\r\n").encode())
        self.assertEqual(status_of(pre), 204, pre)
        self.assertIn(f"Access-Control-Allow-Origin: {ALLOWED_ORIGIN}".encode(), pre)
        self.assertIn(b"Access-Control-Allow-Headers: Content-Type", pre)

        body = b'{"source":"ui","level":"INFO","message":"from dashboard"}'
        ok = post(body, f"Origin: {ALLOWED_ORIGIN}\r\n")
        self.assertEqual(status_of(ok), 201)
        self.assertIn(f"Access-Control-Allow-Origin: {ALLOWED_ORIGIN}".encode(), ok)

        evil = "Origin: http://evil.example\r\n"
        self.assertEqual(status_of(raw_http(
            f"OPTIONS /ingest HTTP/1.1\r\n{evil}\r\n".encode())), 403)
        self.assertEqual(status_of(post(body, evil)), 403)
        # "simple" cross-site form posts (text/plain) are refused too
        self.assertEqual(status_of(post(body, content_type="text/plain")), 415)
        self.assertEqual(status_of(post(body, content_type="")), 415)

    def test_idle_connection_does_not_block(self):
        idle = socket.create_connection(("127.0.0.1", PORT))
        try:
            time.sleep(0.1)
            t0 = time.monotonic()
            resp = raw_http(b"GET /health HTTP/1.1\r\n\r\n")
            elapsed = time.monotonic() - t0
            self.assertIn(b"200 OK", resp)
            self.assertLess(elapsed, 0.5, f"/health took {elapsed:.2f}s with an idle client")
        finally:
            idle.close()

    def test_parallel_ingest_is_consistent(self):
        import concurrent.futures as cf
        body = b'{"source":"par","level":"INFO","message":"parallel"}'
        with cf.ThreadPoolExecutor(16) as ex:
            codes = list(ex.map(lambda _: status_of(post(body)), range(64)))
        self.assertEqual(codes.count(201), 64, codes)
        with sqlite3.connect(self.db) as c:
            n = c.execute("SELECT COUNT(*) FROM events WHERE source='par'").fetchone()[0]
        self.assertEqual(n, 64)

    def test_cli_mode_rejects_invalid_utf8(self):
        db = Path(self.tmp.name) / "cli.db"
        r = subprocess.run(
            [str(INGESTOR_BIN), "--db", str(db), "--schema", str(SCHEMA_PATH), "--ingest",
             "--source", "cli", "--level", "INFO", b"--message".decode(), os.fsdecode(b"bad \xff")],
            capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"INVALID_MESSAGE", r.stderr.upper().replace(b" ", b"_"))

    def test_database_private_under_umask_022(self):
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.db) + suffix)
            if p.exists():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600, p.name)


class TestShutdownWithBusyWorkers(unittest.TestCase):
    """Re-audit #1: SIGTERM while requests wait on a locked database."""

    SHUT_PORT = 18994

    def test_sigterm_cancels_workers_before_closing_db(self):
        with tempfile.TemporaryDirectory(prefix="cerberus_shutdown_") as tmp:
            db = Path(tmp) / "locked.db"
            proc = subprocess.Popen(
                [str(INGESTOR_BIN), "--db", str(db), "--schema", str(SCHEMA_PATH),
                 "--serve", str(self.SHUT_PORT)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        socket.create_connection(("127.0.0.1", self.SHUT_PORT), timeout=1).close()
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail("ingestor did not start")
                        time.sleep(0.05)

                # A foreign writer holds the lock: every insert has to wait.
                lock = sqlite3.connect(db, isolation_level=None)
                lock.execute("BEGIN IMMEDIATE")

                results = []
                body = b'{"source":"s","level":"ERROR","message":"m","webhook_url":"https://example.com/h"}'

                def send():
                    try:
                        with socket.create_connection(("127.0.0.1", self.SHUT_PORT), timeout=15) as s:
                            s.sendall(b"POST /ingest HTTP/1.1\r\nContent-Type: application/json\r\n"
                                      b"Content-Length: %d\r\n\r\n" % len(body) + body)
                            out = b""
                            while True:
                                chunk = s.recv(4096)
                                if not chunk:
                                    break
                                out += chunk
                        results.append(out)
                    except OSError as e:
                        results.append(repr(e).encode())

                threads = [threading.Thread(target=send) for _ in range(3)]
                for t in threads:
                    t.start()
                time.sleep(0.5)  # workers are now blocked on the lock / DB mutex

                t0 = time.monotonic()
                proc.send_signal(signal.SIGTERM)
                rc = proc.wait(timeout=15)
                elapsed = time.monotonic() - t0
                for t in threads:
                    t.join(timeout=5)
                lock.execute("ROLLBACK")
                lock.close()
                stderr = proc.stderr.read()
                proc.stderr.close()

                self.assertEqual(rc, 0, stderr)
                self.assertLess(elapsed, 4.5, f"shutdown took {elapsed:.2f}s")
                self.assertEqual(len(results), 3, results)
                for r in results:
                    self.assertTrue(r.startswith(b"HTTP/1.1 503"), r)
                self.assertIn(b"cancelling_workers", stderr)
                # nothing half-written, database still healthy
                with sqlite3.connect(db) as c:
                    self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
                    self.assertEqual(c.execute("SELECT COUNT(*) FROM alert_deliveries").fetchone()[0], 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                if not proc.stderr.closed:
                    proc.stderr.close()

    def _start(self, db: Path):
        proc = subprocess.Popen(
            [str(INGESTOR_BIN), "--db", str(db), "--schema", str(SCHEMA_PATH),
             "--serve", str(self.SHUT_PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while True:
            try:
                socket.create_connection(("127.0.0.1", self.SHUT_PORT), timeout=1).close()
                return proc
            except OSError:
                if time.monotonic() > deadline:
                    proc.kill()
                    proc.wait()
                    self.fail("ingestor did not start")
                time.sleep(0.05)

    def test_sigterm_without_requests_exits_quickly(self):
        with tempfile.TemporaryDirectory(prefix="cerberus_shutdown_") as tmp:
            proc = self._start(Path(tmp) / "free.db")
            try:
                t0 = time.monotonic()
                proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(timeout=10), 0)
                self.assertLess(time.monotonic() - t0, 1.0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def test_valid_request_in_flight_finishes_during_grace(self):
        """A valid POST that is still running when SIGTERM arrives, and can
        finish inside the grace period, must get 201 and be stored once."""
        with tempfile.TemporaryDirectory(prefix="cerberus_shutdown_") as tmp:
            db = Path(tmp) / "grace.db"
            proc = self._start(db)
            try:
                lock = sqlite3.connect(db, isolation_level=None)
                lock.execute("BEGIN IMMEDIATE")   # keeps the request waiting
                result = []
                body = b'{"source":"grace","level":"INFO","message":"in flight"}'

                def send():
                    with socket.create_connection(("127.0.0.1", self.SHUT_PORT), timeout=15) as s:
                        s.sendall(b"POST /ingest HTTP/1.1\r\nContent-Type: application/json\r\n"
                                  b"Content-Length: %d\r\n\r\n" % len(body) + body)
                        out = b""
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            out += chunk
                    result.append(out)

                t = threading.Thread(target=send)
                t.start()
                time.sleep(0.3)                    # request is now in flight
                proc.send_signal(signal.SIGTERM)
                time.sleep(0.4)                    # still inside the 1.5 s grace
                lock.execute("ROLLBACK")           # let it finish
                lock.close()
                rc = proc.wait(timeout=10)
                t.join(timeout=5)

                self.assertEqual(rc, 0)
                self.assertEqual(len(result), 1)
                self.assertTrue(result[0].startswith(b"HTTP/1.1 201"), result[0])
                with sqlite3.connect(db) as c:
                    n = c.execute("SELECT COUNT(*) FROM events WHERE source='grace'").fetchone()[0]
                self.assertEqual(n, 1)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

class TestDatabasePathPolicy(unittest.TestCase):
    """Re-audit #2 (C side): "file:..." used to be skipped by the 0600 policy
    and SQLite then created a literal 0644 file named e.g. "file::memory:"."""

    def test_sqlite_uris_are_rejected_and_create_nothing(self):
        with tempfile.TemporaryDirectory(prefix="cerberus_uri_") as tmp:
            for dsn in ("file::memory:", "file::memory:disk", "file::memory:disk?mode=rwc",
                        f"file:{tmp}/uri.db", "file:rel.db"):
                r = subprocess.run(
                    ["sh", "-c", 'umask 022; exec "$@"', "sh", str(INGESTOR_BIN), "--db", dsn,
                     "--ingest", "--source", "s", "--level", "INFO", "--message", "m"],
                    cwd=tmp, capture_output=True)
                self.assertNotEqual(r.returncode, 0, dsn)
            self.assertEqual(os.listdir(tmp), [])

    def test_memory_database_creates_no_file(self):
        with tempfile.TemporaryDirectory(prefix="cerberus_uri_") as tmp:
            r = subprocess.run(
                [str(INGESTOR_BIN), "--db", ":memory:", "--ingest",
                 "--source", "s", "--level", "INFO", "--message", "m"],
                cwd=tmp, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.listdir(tmp), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
