#!/usr/bin/env python3
"""
Detects (and optionally repairs) rows with invalid UTF-8 in a Cerberus DB.

Rows like these were accepted by the C ingestor before the audit fix and make
strict readers fail ("invalid utf-8 sequence").

  python3 tools/repair_utf8.py --db data/cerberus.db          # report only
  python3 tools/repair_utf8.py --db data/cerberus.db --fix    # backup + repair

--fix first writes a backup (<db>.bak-<timestamp>, mode 0600) and then
replaces each invalid byte sequence with U+FFFD inside one transaction.
FTS5 stays in sync through the existing UPDATE trigger. Stop the services
(./cerberus.sh stop) before using --fix.
"""

import argparse
import os
import sqlite3
import sys
import time

COLUMNS = {
    "events": ("source", "message", "metadata_json"),
    "alert_deliveries": ("target_url", "last_error"),
}


def is_valid(value) -> bool:
    if not isinstance(value, bytes):
        return True
    try:
        value.decode("utf-8", errors="strict")  # rejects overlongs and surrogates
        return True
    except UnicodeDecodeError:
        return False


def find_bad_rows(conn):
    bad = []
    for table, cols in COLUMNS.items():
        for row in conn.execute(f"SELECT id, {', '.join(cols)} FROM {table}"):
            broken = [c for c, v in zip(cols, row[1:]) if not is_valid(v)]
            if broken:
                bad.append((table, row[0], broken, dict(zip(cols, row[1:]))))
    return bad


def backup(db_path: str) -> str:
    dest = f"{db_path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with sqlite3.connect(db_path) as src, sqlite3.connect(dest) as dst:
        src.backup(dst)
    os.chmod(dest, 0o600)
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--fix", action="store_true", help="repair rows (creates a backup first)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"database not found: {args.db}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(args.db)
    conn.text_factory = bytes  # read raw bytes, never fail on decode
    bad = find_bad_rows(conn)
    for table, row_id, cols, _ in bad:
        print(f"{table} id={row_id}: invalid UTF-8 in {', '.join(cols)}")
    print(f"{len(bad)} row(s) with invalid UTF-8")

    if not bad or not args.fix:
        return 1 if bad else 0

    print(f"backup written to {backup(args.db)}")
    failed = 0
    with conn:
        for table, row_id, cols, values in bad:
            sets = ", ".join(f"{c} = ?" for c in cols)
            fixed = [values[c].decode("utf-8", errors="replace") for c in cols]
            try:
                conn.execute(f"UPDATE {table} SET {sets} WHERE id = ?", (*fixed, row_id))
            except sqlite3.IntegrityError as exc:  # e.g. length CHECK after replacement
                failed += 1
                print(f"could not repair {table} id={row_id}: {exc}", file=sys.stderr)
    remaining = len(find_bad_rows(conn))
    print(f"repaired {len(bad) - failed} row(s); remaining invalid: {remaining}")
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
