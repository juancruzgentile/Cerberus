import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class TestCerberusSchema(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_cerberus.db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        self.conn.executescript(schema_sql)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_pragmas_wal_and_foreign_keys(self):
        """Verifica que el modo WAL y Foreign Keys estén activos."""
        journal_mode = self.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

        fk_enabled = self.conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        self.assertEqual(fk_enabled, 1)

    def test_events_crud_and_fts5_sync(self):
        """Verifica inserción, actualización y borrado en events y sincronización con events_fts."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
            ("auth-service", "ERROR", "Failed login attempt for root", '{"ip": "10.0.0.5"}'),
        )
        event_id = cur.lastrowid
        self.conn.commit()

        # Búsqueda en FTS5 tras INSERT
        fts_rows = cur.execute(
            "SELECT rowid, source, level, message, metadata_json FROM events_fts WHERE events_fts MATCH ?",
            ("login",),
        ).fetchall()
        self.assertEqual(len(fts_rows), 1)
        self.assertEqual(fts_rows[0]["rowid"], event_id)
        self.assertEqual(fts_rows[0]["source"], "auth-service")

        # Búsqueda en FTS5 tras UPDATE
        cur.execute(
            "UPDATE events SET message = ?, level = ? WHERE id = ?",
            ("Database connection timeout", "CRITICAL", event_id),
        )
        self.conn.commit()

        old_match = cur.execute(
            "SELECT rowid FROM events_fts WHERE events_fts MATCH ?", ("login",)
        ).fetchall()
        self.assertEqual(len(old_match), 0)

        new_match = cur.execute(
            "SELECT rowid, level, message FROM events_fts WHERE events_fts MATCH ?",
            ("timeout",),
        ).fetchall()
        self.assertEqual(len(new_match), 1)
        self.assertEqual(new_match[0]["rowid"], event_id)
        self.assertEqual(new_match[0]["level"], "CRITICAL")

        # Búsqueda en FTS5 tras DELETE
        cur.execute("DELETE FROM events WHERE id = ?", (event_id,))
        self.conn.commit()

        deleted_match = cur.execute(
            "SELECT rowid FROM events_fts WHERE events_fts MATCH ?", ("timeout",)
        ).fetchall()
        self.assertEqual(len(deleted_match), 0)

        # Verificar integridad del índice FTS5 con el comando 'integrity-check'
        cur.execute("INSERT INTO events_fts(events_fts) VALUES('integrity-check');")

    def test_events_boundary_lengths_and_constraints(self):
        """Verifica límites exactos permitidos y rechazos en source, message, metadata_json y level."""
        cur = self.conn.cursor()

        # Longitudes máximas exactas permitidas: source=128, message=8192, metadata_json=16384
        max_source = "s" * 128
        max_message = "m" * 8192
        # Crear un JSON válido de longitud exactamente 16384: '{"k":"' (6 chars) + 'v'*16376 + '"}' (2 chars) = 16384
        max_metadata = '{"k":"' + ("v" * 16376) + '"}'
        self.assertEqual(len(max_metadata), 16384)

        cur.execute(
            "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
            (max_source, "INFO", max_message, max_metadata),
        )
        self.conn.commit()

        # Rechazo de source vacío y > 128
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("", "INFO", "valid message"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("s" * 129, "INFO", "valid message"),
            )

        # Rechazo de message vacío y > 8192
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("valid-source", "INFO", ""),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("valid-source", "INFO", "m" * 8193),
            )

        # Rechazo de metadata_json > 16384 (aunque sea JSON válido)
        over_metadata = '{"k":"' + ("v" * 16377) + '"}'
        self.assertEqual(len(over_metadata), 16385)
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
                ("valid-source", "INFO", "valid message", over_metadata),
            )

        # Rechazo de level inválido
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
                ("valid-source", "TRACE", "valid message"),
            )

    def test_metadata_json_validation(self):
        """Verifica que json_valid(metadata_json) rechace JSON malformado y acepte JSON válido o por defecto."""
        cur = self.conn.cursor()

        # Valor por defecto '{}'
        cur.execute(
            "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
            ("sensor-1", "DEBUG", "ping"),
        )
        row = cur.execute(
            "SELECT metadata_json, created_at FROM events WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        self.assertEqual(row["metadata_json"], "{}")
        self.assertGreater(row["created_at"], 0)

        # JSON inválido o vacío
        for invalid_json in ["", "{invalid_json}", "{'single': 'quotes'}", "{\"unclosed\": 1"]:
            with self.subTest(invalid_json=invalid_json):
                with self.assertRaises(sqlite3.IntegrityError):
                    cur.execute(
                        "INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)",
                        ("sensor-1", "WARN", "bad json test", invalid_json),
                    )

    def test_alert_deliveries_lifecycle_and_cascade(self):
        """Verifica ciclo de vida de alert_deliveries, restricciones y borrado ON DELETE CASCADE."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (source, level, message) VALUES (?, ?, ?)",
            ("firewall", "CRITICAL", "Intrusion detected"),
        )
        event_id = cur.lastrowid

        # Inserción válida con valores por defecto
        cur.execute(
            "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
            (event_id, "https://hooks.example.com/alert"),
        )
        delivery_id = cur.lastrowid
        self.conn.commit()

        delivery = cur.execute(
            "SELECT * FROM alert_deliveries WHERE id = ?", (delivery_id,)
        ).fetchone()
        self.assertEqual(delivery["status"], "PENDING")
        self.assertEqual(delivery["attempts"], 0)
        self.assertEqual(delivery["max_attempts"], 3)
        self.assertEqual(delivery["last_error"], "")

        # Transiciones de estado (PENDING -> FAILED -> SENT -> DEAD)
        cur.execute(
            "UPDATE alert_deliveries SET status = 'FAILED', attempts = 1, last_error = 'HTTP 502' WHERE id = ?",
            (delivery_id,),
        )
        cur.execute(
            "UPDATE alert_deliveries SET status = 'SENT', attempts = 2, last_error = '' WHERE id = ?",
            (delivery_id,),
        )
        self.conn.commit()

        # Restricciones en alert_deliveries (event_id inexistente, URL inválida, status inválido, attempts < 0, max_attempts fuera de rango, last_error > 2048)
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
                (999999, "https://hooks.example.com/alert"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
                (event_id, "ftp://hooks.example.com/alert"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url) VALUES (?, ?)",
                (event_id, "https://" + ("a" * 1018)),  # 8 + 1018 = 1026 > 1024
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url, status) VALUES (?, ?, ?)",
                (event_id, "http://localhost:8080/hook", "UNKNOWN"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url, attempts) VALUES (?, ?, ?)",
                (event_id, "http://localhost:8080/hook", -1),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url, max_attempts) VALUES (?, ?, ?)",
                (event_id, "http://localhost:8080/hook", 0),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url, max_attempts) VALUES (?, ?, ?)",
                (event_id, "http://localhost:8080/hook", 11),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            cur.execute(
                "INSERT INTO alert_deliveries (event_id, target_url, last_error) VALUES (?, ?, ?)",
                (event_id, "http://localhost:8080/hook", "e" * 2049),
            )

        # Borrado en cascada (ON DELETE CASCADE) al borrar el evento padre
        cur.execute("DELETE FROM events WHERE id = ?", (event_id,))
        self.conn.commit()

        remaining = cur.execute(
            "SELECT count(*) FROM alert_deliveries WHERE event_id = ?", (event_id,)
        ).fetchone()[0]
        self.assertEqual(remaining, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
