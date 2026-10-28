#!/usr/bin/env python3
"""
Cerberus — tests of the cerberus.sh launcher (re-audit #3).

Before the fix, any 200 on /health ended wait_health(): with a foreign server
answering on the Search port, Search died with "Address already in use" but
`start` exited 0, announced the dashboard and left the other services running.

Re-audit (2nd round): replacing a binary while it runs (recompiling) made
`stop` lose control of the service: /proc/<pid>/exe became "... (deleted)",
`stop` exited 0, deleted the PID file and left the process alive.

Safety: each test runs a PRIVATE COPY of cerberus.sh, the schema and the three
binaries inside a temporary directory, with its own RUN_DIR, database and free
ports. The project's real binaries, data/ and run/ are never touched, and the
only processes ever signalled are the ones the test itself started (the
teardown double-checks that nothing launched from the temporary copy is left).
Requires the binaries (make build) and Linux (/proc).
"""

import http.server
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARIES = {
    "ingestor": Path("ingestor-c/bin/cerberus-ingestor"),
    "alerter": Path("alerter-go/bin/cerberus-alerter"),
    "search": Path("search-rust/target/release/cerberus-search"),
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Impostor:
    """Foreign HTTP server that answers 200 to everything (incl. /health)."""

    def __init__(self, port: int):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()


class LauncherTestCase(unittest.TestCase):
    # Spaces on purpose: the real project lives in ".../Carpeta principal/Juan Cruz/...".
    ROOT_NAME = "copia con espacios"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cerberus_launcher_")
        base = Path(self.tmp.name)
        # Private copy of the launcher + binaries: tests may replace them freely.
        self.root = base / self.ROOT_NAME
        (self.root / "schema").mkdir(parents=True)
        shutil.copy2(ROOT / "cerberus.sh", self.root / "cerberus.sh")
        shutil.copy2(ROOT / "schema" / "schema.sql", self.root / "schema" / "schema.sql")
        self.bins = {}
        for name, rel in BINARIES.items():
            dst = self.root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, dst)
            self.bins[name] = dst
        self.launcher_path = self.root / "cerberus.sh"
        self.helpers = []  # extra processes started by a test (always killed)

        self.run_dir = base / "run"
        self.ports = {
            "ingest": free_port(),
            "search": free_port(),
            "metrics": free_port(),
        }
        self.env = dict(
            os.environ,
            CERBERUS_DB=str(base / "data" / "cerberus.db"),
            CERBERUS_RUN_DIR=str(self.run_dir),
            CERBERUS_INGEST_PORT=str(self.ports["ingest"]),
            CERBERUS_SEARCH_PORT=str(self.ports["search"]),
            CERBERUS_METRICS_PORT=str(self.ports["metrics"]),
            CERBERUS_HEALTH_TIMEOUT="4",
        )

    def tearDown(self):
        subprocess.run([str(self.launcher_path), "stop"], env=self.env,
                       capture_output=True, timeout=30)
        for p in self.helpers:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=10)
        # Safety net: only processes whose executable lives in OUR temp copy.
        prefix = str(self.root) + os.sep
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                exe = os.readlink(entry / "exe")
            except OSError:
                continue
            if exe.startswith(prefix):
                try:
                    os.kill(int(entry.name), 9)
                except ProcessLookupError:
                    pass
        self.tmp.cleanup()

    def launcher(self, *args, timeout=60):
        return subprocess.run([str(self.launcher_path), *args], env=self.env,
                              capture_output=True, text=True, timeout=timeout)

    def service_pids(self):
        pids = {}
        for name in ("ingestor", "alerter", "search"):
            pf = self.run_dir / f"{name}.pid"
            if pf.exists():
                pids[name] = int(pf.read_text().split()[0])
        return pids

    @staticmethod
    def alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        stat = Path(f"/proc/{pid}/stat")
        return stat.exists() and stat.read_text().split(") ")[1][0] != "Z"


class TestLauncherStart(LauncherTestCase):
    def test_start_succeeds_and_owns_every_port(self):
        r = self.launcher("start")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Web Dashboard", r.stdout)
        pids = self.service_pids()
        self.assertEqual(set(pids), {"ingestor", "alerter", "search"})
        for pid in pids.values():
            self.assertTrue(self.alive(pid))
        st = self.launcher("status")
        self.assertEqual(st.stderr.count("detenido"), 0, st.stdout + st.stderr)

    def test_occupied_search_port_answering_200_is_a_failed_start(self):
        with Impostor(self.ports["search"]):
            r = self.launcher("start")
            out = r.stdout + r.stderr
            self.assertNotEqual(r.returncode, 0, out)
            self.assertNotIn("Web Dashboard", out)
            self.assertIn(str(self.ports["search"]), out)
            self.assertIn("Arranque fallido", out)
            # rollback: nothing started by this attempt is left running
            time.sleep(0.3)
            for name in ("ingestor", "alerter", "search"):
                self.assertFalse((self.run_dir / f"{name}.pid").exists(), name)
            for port in (self.ports["ingest"], self.ports["metrics"]):
                with socket.socket() as s:
                    self.assertNotEqual(s.connect_ex(("127.0.0.1", port)), 0, port)
            # the foreign server was not touched
            with socket.create_connection(("127.0.0.1", self.ports["search"]), timeout=2):
                pass

    def test_occupied_ingest_port_fails_before_starting_anything(self):
        with Impostor(self.ports["ingest"]):
            r = self.launcher("start")
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("ocupado", r.stderr)
            self.assertEqual(self.service_pids(), {})


class TestWaitHealthOwnership(LauncherTestCase):
    """The race the pre-check cannot close: our process is alive, but the port
    that answers 200 belongs to someone else. wait_health() must refuse it."""

    def test_live_process_that_does_not_own_the_port_is_rejected(self):
        own_port = free_port()
        db = Path(self.env["CERBERUS_DB"])
        db.parent.mkdir(parents=True)
        # A genuine cerberus-search process, listening on ANOTHER port.
        proc = subprocess.Popen(
            [str(self.bins["search"]), "--db", str(db), "--schema", str(ROOT / "schema" / "schema.sql"),
             "--serve", str(own_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                with socket.socket() as s:
                    if s.connect_ex(("127.0.0.1", own_port)) == 0:
                        break
                if time.monotonic() > deadline:
                    self.fail("cerberus-search did not start")
                time.sleep(0.05)

            script = r'''
                source "$1"
                mkdir -p "$RUN_DIR"
                start="$(proc_starttime "$2")"
                printf '%s %s %s %s\n' "$2" "$start" "$(exe_ident "/proc/$2/exe")" "$SEARCH_BIN" >"$(pid_file search)"
                rc=0; wait_health "http://127.0.0.1:$3/health" search "$3" || rc=$?
                echo "impostor_rc=$rc"
                rc=0; wait_health "http://127.0.0.1:$4/health" search "$4" || rc=$?
                echo "own_rc=$rc"
            '''
            with Impostor(self.ports["search"]):
                r = subprocess.run(
                    ["bash", "-c", script, "bash", str(self.launcher_path), str(proc.pid),
                     str(self.ports["search"]), str(own_port)],
                    env=dict(self.env, CERBERUS_HEALTH_TIMEOUT="2"),
                    capture_output=True, text=True, timeout=30)
            self.assertIn("impostor_rc=1", r.stdout, r.stdout + r.stderr)
            self.assertIn("no pertenece al proceso lanzado", r.stderr)
            self.assertIn("own_rc=0", r.stdout, r.stdout + r.stderr)
        finally:
            (self.run_dir / "search.pid").unlink(missing_ok=True)
            proc.terminate()
            proc.wait(timeout=10)


class TestStopOwnership(LauncherTestCase):
    """2nd re-audit: identity must survive a binary replacement, and a record
    that cannot be proven must be kept (and reported), never killed."""

    def replace_binary(self, name: str):
        """Simulates a rebuild: new file (new inode) atomically renamed over the old one."""
        path = self.bins[name]
        tmp = path.with_name(path.name + ".new")
        shutil.copy2(path, tmp)
        os.replace(tmp, path)

    def test_stop_after_binary_replaced_still_stops_the_service(self):
        r = self.launcher("start")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pid = self.service_pids()["alerter"]
        self.replace_binary("alerter")
        self.assertTrue(os.readlink(f"/proc/{pid}/exe").endswith("(deleted)"))

        st = self.launcher("status")
        self.assertIn(f"alerter en ejecución (pid {pid})", st.stdout, st.stdout + st.stderr)

        r = self.launcher("stop")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        deadline = time.monotonic() + 5
        while self.alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.alive(pid), "alerter survived stop after binary replacement")
        self.assertEqual(self.service_pids(), {})

    def test_unprovable_record_is_kept_and_its_process_is_not_killed(self):
        # A foreign process (sleep) recorded with the right PID and starttime but
        # whose executable is not the alerter binary: ownership cannot be proven.
        sleeper = subprocess.Popen(["sleep", "60"])
        self.helpers.append(sleeper)
        self.run_dir.mkdir(parents=True)
        start = Path(f"/proc/{sleeper.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        st = os.stat(self.bins["alerter"])
        pf = self.run_dir / "alerter.pid"
        pf.write_text(f"{sleeper.pid} {start} {st.st_dev}:{st.st_ino} {self.bins['alerter']}\n")

        r = self.launcher("stop")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no se mata nada", r.stderr)
        self.assertTrue(self.alive(sleeper.pid), "foreign process was killed")
        self.assertTrue(pf.exists(), "unprovable record was deleted")

        st_out = self.launcher("status")
        self.assertIn("sin propiedad acreditada", st_out.stderr)

        # start refuses to launch a second alerter and rolls back the ingestor
        r = self.launcher("start")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no se puede acreditar", r.stderr)
        self.assertTrue(self.alive(sleeper.pid))
        self.assertTrue(pf.exists())
        self.assertFalse((self.run_dir / "ingestor.pid").exists())

        pf.unlink()  # let tearDown's stop succeed; the sleeper is killed there

    def test_reused_pid_record_is_removed_without_killing(self):
        # Same PID as a live foreign process but a different starttime -> stale.
        sleeper = subprocess.Popen(["sleep", "60"])
        self.helpers.append(sleeper)
        self.run_dir.mkdir(parents=True)
        st = os.stat(self.bins["search"])
        pf = self.run_dir / "search.pid"
        pf.write_text(f"{sleeper.pid} 1 {st.st_dev}:{st.st_ino} {self.bins['search']}\n")
        r = self.launcher("stop")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("obsoleto", r.stdout)
        self.assertTrue(self.alive(sleeper.pid))
        self.assertFalse(pf.exists())


class LegacyRecordMixin:
    """3rd re-audit: records written by the previous launcher ("pid starttime
    path") broke when the path contained spaces: stop exited 1 and left the
    service running."""

    def test_legacy_pid_record_is_still_stopped(self):
        r = self.launcher("start")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pids = self.service_pids()
        for name, pid in pids.items():
            start = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
            (self.run_dir / f"{name}.pid").write_text(
                f"{pid} {start} {os.path.realpath(self.bins[name])}\n")

        st = self.launcher("status")
        for name, pid in pids.items():
            self.assertIn(f"{name} en ejecución (pid {pid})", st.stdout, st.stdout + st.stderr)

        r = self.launcher("stop")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        deadline = time.monotonic() + 5
        while any(self.alive(p) for p in pids.values()) and time.monotonic() < deadline:
            time.sleep(0.05)
        for name, pid in pids.items():
            self.assertFalse(self.alive(pid), f"{name} survived stop with a legacy record")
        self.assertEqual(self.service_pids(), {})

    def test_legacy_record_of_foreign_process_is_kept(self):
        sleeper = subprocess.Popen(["sleep", "60"])
        self.helpers.append(sleeper)
        self.run_dir.mkdir(parents=True)
        start = Path(f"/proc/{sleeper.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        pf = self.run_dir / "alerter.pid"
        pf.write_text(f"{sleeper.pid} {start} {os.path.realpath(self.bins['alerter'])}\n")
        r = self.launcher("stop")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.alive(sleeper.pid))
        self.assertTrue(pf.exists())
        pf.unlink()


class TestLegacyRecordPathWithSpaces(LegacyRecordMixin, LauncherTestCase):
    ROOT_NAME = "copia con espacios"


class TestLegacyRecordPathWithoutSpaces(LegacyRecordMixin, LauncherTestCase):
    ROOT_NAME = "copia_sin_espacios"


if __name__ == "__main__":
    unittest.main(verbosity=2)
