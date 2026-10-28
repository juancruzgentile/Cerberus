#!/usr/bin/env python3
"""
Cerberus — Suite de Integración End-to-End Políglota.

Verifica que las 3 cabezas trabajen juntas sobre la MISMA base SQLite (WAL):

    [cliente] --POST /ingest--> C11 ingestor --> events + alert_deliveries
                                                      |
                     Go alerter --once  <-------------+--> webhook receptor (HMAC)
                                                      |
                     Rust search --serve <------------+--> /search (BM25) y /summary

Requisitos: `make build` previo (el target `make e2e` ya lo hace).
"""
import hashlib
import hmac
import http.server
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schema" / "schema.sql"
INGESTOR_BIN = ROOT / "ingestor-c" / "bin" / "cerberus-ingestor"
ALERTER_BIN = ROOT / "alerter-go" / "bin" / "cerberus-alerter"
SEARCH_BIN = ROOT / "search-rust" / "target" / "release" / "cerberus-search"

WEBHOOK_SECRET = "e2e-test-secret-not-for-production"
STARTUP_TIMEOUT_S = 10.0


def free_port() -> int:
    """Devuelve un puerto TCP libre en loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_health(port: int, timeout: float = STARTUP_TIMEOUT_S) -> None:
    """Espera hasta que GET /health responda 200 o falla."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last_err = exc
        time.sleep(0.1)
    raise RuntimeError(f"Servicio en puerto {port} no respondió /health: {last_err}")


def http_json(method: str, url: str, payload=None):
    """Petición HTTP simple que devuelve (status, json)."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        with e:
            body = e.read().decode()
        return e.code, json.loads(body) if body else {}


class WebhookReceiver:
    """Receptor de webhooks local que registra cuerpo y cabeceras."""

    def __init__(self):
        self.received = []
        self._lock = threading.Lock()
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (API de http.server)
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                with receiver._lock:
                    receiver.received.append({"headers": dict(self.headers), "body": body})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.port = free_port()
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()


class TestCerberusEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for binary in (INGESTOR_BIN, ALERTER_BIN, SEARCH_BIN):
            if not binary.exists():
                raise unittest.SkipTest(f"Falta binario {binary}; ejecute `make build`")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.tmp.name) / "cerberus_e2e.db"
        cls.procs = []

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        cls.tmp.cleanup()

    @classmethod
    def spawn(cls, args, env=None):
        proc = subprocess.Popen(
            [str(a) for a in args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
        )
        cls.procs.append(proc)
        return proc

    def db(self):
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def test_full_pipeline_c_go_rust(self):
        with WebhookReceiver() as receiver:
            good_hook = f"http://127.0.0.1:{receiver.port}/hook"
            dead_hook = f"http://127.0.0.1:{free_port()}/down"  # puerto sin servicio

            # ---------------- Cabeza 1: C11 ingestor ----------------
            ingest_port = free_port()
            search_port = free_port()
            dashboard_origin = f"http://127.0.0.1:{search_port}"
            self.spawn([INGESTOR_BIN, "--db", self.db_path, "--schema", SCHEMA,
                        "--serve", ingest_port, "--cors-origin", dashboard_origin])
            wait_for_health(ingest_port)
            self.assertEqual(oct(os.stat(self.db_path).st_mode & 0o777), "0o600")

            events = [
                {"source": "auth-service", "level": "INFO",
                 "message": "User login succeeded for alice"},
                {"source": "auth-service", "level": "WARN",
                 "message": "Slow response from identity provider"},
                {"source": "payment-api", "level": "ERROR",
                 "message": "Database deadlock detected in payment ledger",
                 "metadata": {"region": "eu-west-1"}, "webhook_url": good_hook},
                {"source": "payment-api", "level": "CRITICAL",
                 "message": "Payment gateway unreachable kraken_e2e_marker",
                 "webhook_url": dead_hook},
            ]
            ids = []
            for ev in events:
                status, body = http_json("POST", f"http://127.0.0.1:{ingest_port}/ingest", ev)
                self.assertIn(status, (200, 201), body)
                self.assertEqual(body.get("status"), "ok")
                ids.append(body["event_id"])

            # Ataque SSRF a través de la cabeza C debe ser rechazado.
            status, _ = http_json("POST", f"http://127.0.0.1:{ingest_port}/ingest", {
                "source": "attacker", "level": "CRITICAL", "message": "ssrf",
                "webhook_url": "http://169.254.169.254/latest/meta-data/"})
            self.assertEqual(status, 400)

            with self.db() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 4)
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM alert_deliveries WHERE status='PENDING'").fetchone()[0], 2)

            # ---------------- Cabeza 2: Go alerter ----------------
            env = dict(os.environ, CERBERUS_WEBHOOK_SECRET=WEBHOOK_SECRET)
            result = subprocess.run(
                [str(ALERTER_BIN), "--db", str(self.db_path), "--once",
                 "--allow-loopback", "--timeout", "1s"],
                env=env, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

            self.assertEqual(len(receiver.received), 1, "Solo el webhook sano debe recibir")
            delivery = receiver.received[0]
            expected_sig = "sha256=" + hmac.new(
                WEBHOOK_SECRET.encode(), delivery["body"], hashlib.sha256).hexdigest()
            self.assertTrue(hmac.compare_digest(
                delivery["headers"].get("X-Cerberus-Signature-256", ""), expected_sig))
            payload = json.loads(delivery["body"])
            self.assertEqual(payload["event_id"], ids[2])
            self.assertEqual(payload["level"], "ERROR")

            with self.db() as conn:
                rows = dict(conn.execute(
                    "SELECT event_id, status FROM alert_deliveries").fetchall())
            self.assertEqual(rows[ids[2]], "SENT")
            self.assertIn(rows[ids[3]], ("FAILED", "DEAD"))

        # ---------------- Cabeza 3: Rust search ----------------
        self.spawn([SEARCH_BIN, "--db", self.db_path, "--serve", search_port,
                    "--ingest-url", f"http://127.0.0.1:{ingest_port}"])
        wait_for_health(search_port)

        q = urllib.parse.urlencode({"q": "deadlock"})
        status, body = http_json("GET", f"http://127.0.0.1:{search_port}/search?{q}")
        self.assertEqual(status, 200)
        self.assertEqual(body["total_matches"], 1)
        self.assertEqual(body["results"][0]["id"], ids[2])
        self.assertIn("[deadlock]", body["results"][0]["snippet"].lower())

        q = urllib.parse.urlencode({"q": "kraken*", "level": "CRITICAL"})
        status, body = http_json("GET", f"http://127.0.0.1:{search_port}/search?{q}")
        self.assertEqual(status, 200)
        self.assertEqual(body["total_matches"], 1)

        status, summary = http_json("GET", f"http://127.0.0.1:{search_port}/summary")
        self.assertEqual(status, 200)
        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(summary["events_by_level"],
                         {"debug": 0, "info": 1, "warn": 1, "error": 1, "critical": 1})
        self.assertEqual(summary["alerts"]["total"], 2)
        self.assertEqual(summary["alerts"]["sent"], 1)
        self.assertEqual(summary["alerts"]["failed"] + summary["alerts"]["dead"], 1)
        self.assertEqual({s["source"] for s in summary["top_sources"]},
                         {"auth-service", "payment-api"})

        # ---------------- Web UI Minimalista Embebida (Rust) ----------------
        req_ui = urllib.request.Request(f"http://127.0.0.1:{search_port}/")
        with urllib.request.urlopen(req_ui, timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertIn("text/html", r.headers.get("Content-Type", ""))
            self.assertIn("DENY", r.headers.get("X-Frame-Options", ""))
            csp = r.headers.get("Content-Security-Policy", "")
            html = r.read().decode()
            self.assertIn("CERBERUS", html)

        # ---------------- Simulador del dashboard (flujo del navegador) ----------------
        # 1) el HTML apunta al ingestor real y la CSP lo permite
        ingest_url = f"http://127.0.0.1:{ingest_port}"
        self.assertIn(f'name="cerberus-ingest-url" content="{ingest_url}"', html)
        self.assertIn(f"connect-src 'self' {ingest_url};", csp)
        # 2) preflight CORS que haría el navegador antes del POST JSON
        pre = urllib.request.Request(f"{ingest_url}/ingest", method="OPTIONS", headers={
            "Origin": dashboard_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
        with urllib.request.urlopen(pre, timeout=5) as r:
            self.assertEqual(r.status, 204)
            self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), dashboard_origin)
            self.assertIn("POST", r.headers.get("Access-Control-Allow-Methods", ""))
            self.assertIn("Content-Type", r.headers.get("Access-Control-Allow-Headers", ""))
        # 3) envío real del formulario con cabecera Origin
        req = urllib.request.Request(
            f"{ingest_url}/ingest", method="POST",
            data=json.dumps({"source": "dashboard", "level": "INFO",
                             "message": "Español: café 日本 😀"}).encode(),
            headers={"Content-Type": "application/json", "Origin": dashboard_origin})
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 201)
            self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), dashboard_origin)
        q = urllib.parse.urlencode({"source": "dashboard"})
        status, body = http_json("GET", f"http://127.0.0.1:{search_port}/search?{q}")
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["message"], "Español: café 日本 😀")
        # 4) otro origen no puede escribir
        evil = urllib.request.Request(
            f"{ingest_url}/ingest", method="POST", data=b'{"source":"x","level":"INFO","message":"x"}',
            headers={"Content-Type": "application/json", "Origin": "http://evil.example"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(evil, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        ctx.exception.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
