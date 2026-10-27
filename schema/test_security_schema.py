import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSecuritySchema(unittest.TestCase):
    """Suite de auditoría de seguridad (SecOps / AppSec) para el esquema SQLite + FTS5 de Cerberus."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "sec_cerberus.db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        self.conn.executescript(schema_sql)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_sql_injection_in_fields_and_fts5_triggers(self):
        """
        Verifica que payloads de inyección SQL en source, message y metadata_json
        insertados vía consultas parametrizadas se almacenen literalmente sin
        ejecutar comandos maliciosos ni corromper los triggers hacia events_fts.
        """
        cur = self.conn.cursor()
        sqli_payloads = [
            "'; DROP TABLE events; --",
            "\" OR 1=1; DELETE FROM alert_deliveries; --",
            "'); INSERT INTO events (source, level, message) VALUES ('pwn', 'CRITICAL', 'pwn'); --",
            "admin' UNION SELECT 1,2,3,4,5 --",
        ]

        for idx, payload in enumerate(sqli_payloads):
            source_val = f"src-{idx}-{payload}"[:128]
            msg_val = f"msg: {payload}"
            meta_val = sqlite3.connect(":memory:").execute(
                "SELECT json_object('payload', ?)", (payload,)
            ).fetchone()[0]

            cur.execute(
                "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
                (source_val, "WARN", msg_val, meta_val),
            )
            cur.execute(
                "UPDATE events SET message = ? WHERE id = ?",
                (msg_val + " [updated]", cur.lastrowid),
            )

        self.conn.commit()

        # Verificar que las tablas siguen intactas y contienen exactamente los registros esperados
        count = cur.execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertEqual(count, len(sqli_payloads))

        # Verificar integridad del índice FTS5 tras múltiples triggers con caracteres especiales SQL
        cur.execute("INSERT INTO events_fts(events_fts) VALUES('integrity-check');")

        # Verificar que consultas FTS5 parametrizadas con sintaxis segura (frases entre comillas dobles)
        # no permitan inyección SQL fuera del motor FTS5
        malicious_fts_query = '"DROP" OR "UNION"'
        rows = cur.execute(
            "SELECT rowid, message FROM events_fts WHERE events_fts MATCH ?",
            (malicious_fts_query,),
        ).fetchall()
        self.assertGreaterEqual(len(rows), 2)

        # Operadores FTS5 malformados deben lanzar OperationalError controlado y nunca corromper la BD
        with self.assertRaises(sqlite3.OperationalError):
            cur.execute(
                "SELECT rowid FROM events_fts WHERE events_fts MATCH ?",
                ('unclosed "quote OR AND *',),
            ).fetchall()

        # La tabla events sigue intacta después del error de sintaxis FTS5
        self.assertEqual(cur.execute("SELECT count(*) FROM events").fetchone()[0], len(sqli_payloads))

    def test_malformed_json_and_oversized_payload_bombs(self):
        """
        Verifica el rechazo estricto de JSON malformado, tipos JSON no-objeto (escalares/arrays)
        y bombas lógicas de tamaño excesivo (>128B source, >8KB message, >16KB metadata_json).
        """
        cur = self.conn.cursor()

        # 1. JSON malformado o no-objeto (escalares, arrays, null)
        bad_metadata_payloads = [
            "",
            "{bad_json: true}",
            "{'single_quotes': 1}",
            '{"unclosed": "value"',
            "null",
            "true",
            "12345",
            '"just a string"',
            "[1, 2, 3]",
            '{"trailing": "comma",}',
        ]
        for bad_json in bad_metadata_payloads:
            with self.subTest(bad_json=bad_json):
                with self.assertRaises(sqlite3.IntegrityError):
                    cur.execute(
                        "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
                        ("sec-sensor", "ERROR", "Testing bad JSON", bad_json),
                    )

        # 2. Bombas de tamaño (DoS por agotamiento en source, message y metadata_json)
        # source > 128 bytes
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("A" * 129, "ERROR", "Valid message"),
            )

        # message > 8192 bytes (ej. 8193 bytes y bomba de 1MB)
        for size in (8193, 1024 * 1024):
            with self.subTest(message_size=size):
                with self.assertRaises(sqlite3.IntegrityError):
                    cur.execute(
                        "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                        ("sec-sensor", "ERROR", "M" * size),
                    )

        # metadata_json > 16384 bytes (16385 bytes y bomba de 512KB)
        for extra in (1, 512 * 1024):
            with self.subTest(metadata_extra=extra):
                oversized_json = '{"bomb":"' + ("X" * (16375 + extra)) + '"}'
                self.assertGreater(len(oversized_json), 16384)
                with self.assertRaises(sqlite3.IntegrityError):
                    cur.execute(
                        "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
                        ("sec-sensor", "ERROR", "Oversized metadata", oversized_json),
                    )

    def test_ssrf_and_dangerous_schemes_in_target_url(self):
        """
        Verifica que alert_deliveries.target_url rechace esquemas peligrosos
        (file://, javascript:, gopher://, ftp://, data:, dict://), URLs truncadas,
        inyección CRLF/espacios y endpoints de metadatos cloud (169.254.169.254).
        """
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
            ("ids", "CRITICAL", "Test SSRF target_url validation"),
        )
        event_id = cur.lastrowid
        self.conn.commit()

        dangerous_urls = [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "JAVASCRIPT:alert(document.cookie)",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://malicious.example.com/payload",
            "dict://127.0.0.1:11211/stat",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "http://",
            "https://",
            "HTTP://UPPERCASE-SCHEME.example.com/hook",
            "http://example.com/hook\r\nX-Injected: true",
            "http://example.com/hook\nTransfer-Encoding: chunked",
            "http://example.com/hook with spaces",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://169.254.169.254/metadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "https://" + ("a" * 1020),  # Excede 1024 caracteres
        ]

        for bad_url in dangerous_urls:
            with self.subTest(bad_url=bad_url):
                with self.assertRaises(sqlite3.IntegrityError):
                    cur.execute(
                        "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
                        (event_id, bad_url),
                    )

        # Verificar que una URL legítima https:// sí sea permitida
        cur.execute(
            "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
            (event_id, "https://alerts.cerberus.internal/v1/webhook"),
        )
        self.conn.commit()

    def test_repository_secrets_and_permissions_hygiene(self):
        """
        Verifica que .gitignore bloquee bases de datos/WAL/secretos y que no existan
        archivos con permisos inseguros (world-writable) ni secretos expuestos en el repo.
        """
        gitignore_path = REPO_ROOT / ".gitignore"
        self.assertTrue(gitignore_path.is_file(), "Falta archivo .gitignore en la raíz del proyecto")
        gitignore_content = gitignore_path.read_text(encoding="utf-8")

        for pattern in ("*.db", "*.db-wal", "*.db-shm", ".env", "*.pem", "*.key"):
            self.assertIn(pattern, gitignore_content, f"Patrón crítico {pattern} ausente en .gitignore")

        forbidden_extensions = {".pem", ".key", ".p12", ".pfx"}
        for root, dirs, files in os.walk(REPO_ROOT):
            if ".git" in dirs:
                dirs.remove(".git")
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                self.assertNotIn(ext, forbidden_extensions, f"Archivo de clave/secreto detectado: {fpath}")
                self.assertNotEqual(fname, ".env", f"Archivo .env expuesto en repositorio: {fpath}")

                mode = fpath.stat().st_mode
                self.assertEqual(
                    mode & stat.S_IWOTH,
                    0,
                    f"Permisos inseguros (world-writable) en {fpath}: {oct(mode)}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
