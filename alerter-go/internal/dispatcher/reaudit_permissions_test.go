package dispatcher

// Re-audit #2: SQLite URIs and filenames containing "mode=memory" used to
// skip the 0600 policy and leave the database 0644 under umask 022.

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func schemaForTests() string {
	return filepath.Join("..", "..", "..", "schema", "schema.sql")
}

func assertPrivate(t *testing.T, file string) {
	t.Helper()
	for _, p := range []string{file, file + "-wal", file + "-shm"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) && p != file {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s has mode %o, want 600", filepath.Base(p), perm)
		}
	}
}

// The schema must have landed in the very file we protected (not elsewhere).
func assertSchemaIn(t *testing.T, file string) {
	t.Helper()
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'alert_deliveries'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema was not written to %s", file)
	}
}

func TestReaudit_DatabaseIsPrivateForEveryDSNForm(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	dir := t.TempDir()
	esc := (&url.URL{Path: dir}).EscapedPath()
	cases := []struct {
		name, dsn, file string
	}{
		{"plain path", filepath.Join(dir, "ordinary.db"), filepath.Join(dir, "ordinary.db")},
		{"file:/abs URI", "file:" + esc + "/uri.db", filepath.Join(dir, "uri.db")},
		{"file:///abs URI", "file://" + esc + "/uri3.db", filepath.Join(dir, "uri3.db")},
		{"file://localhost URI", "file://localhost" + esc + "/local.db", filepath.Join(dir, "local.db")},
		{"URI with mode=rwc", "file:" + esc + "/rwc.db?mode=rwc", filepath.Join(dir, "rwc.db")},
		{"URI percent-encoded", "file:" + esc + "/with%20space.db", filepath.Join(dir, "with space.db")},
		{"plain name containing mode=memory", filepath.Join(dir, "mode=memory.db"), filepath.Join(dir, "mode=memory.db")},
		{"plain name with driver query", filepath.Join(dir, "q.db") + "?_pragma=foreign_keys(1)", filepath.Join(dir, "q.db")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := OpenAndInitDB(context.Background(), tc.dsn, schemaForTests())
			if err != nil {
				t.Fatalf("OpenAndInitDB(%q): %v", tc.dsn, err)
			}
			// Force WAL/SHM to exist while we check them.
			if _, err := db.Exec(`INSERT INTO events(source, level, message) VALUES ('t','INFO','m')`); err != nil {
				t.Fatal(err)
			}
			assertPrivate(t, tc.file)
			db.Close()
			assertSchemaIn(t, tc.file)
		})
	}

	// "x.db?..." must not leave a stray file literally named "x.db?...".
	if _, err := os.Stat(filepath.Join(dir, "q.db?_pragma=foreign_keys(1)")); !os.IsNotExist(err) {
		t.Fatalf("stray file created for the query part: %v", err)
	}
}

func TestReaudit_InMemoryDSNsCreateNoFile(t *testing.T) {
	dir := t.TempDir()
	for _, dsn := range []string{
		":memory:",
		"file::memory:",
		"file:" + filepath.Join(dir, "mem.db") + "?mode=memory",
	} {
		db, err := OpenAndInitDB(context.Background(), dsn, schemaForTests())
		if err != nil {
			t.Fatalf("OpenAndInitDB(%q): %v", dsn, err)
		}
		db.Close()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("in-memory DSNs created files: %v", entries)
	}
}

func TestReaudit_UnsupportedDSNsAreRejected(t *testing.T) {
	dir := t.TempDir()
	for _, dsn := range []string{
		"file:" + filepath.Join(dir, "a.db") + "?vfs=unix-none",
		filepath.Join(dir, "b.db") + "?vfs=memdb",
		"file:" + filepath.Join(dir, "c.db") + "?mode=ro",
		"file:" + filepath.Join(dir, "d.db") + "?mode=rwc&mode=memory",
		"file://evil.example/" + filepath.Join(dir, "e.db"),
		"file:",
		"file:?mode=rwc",
	} {
		db, err := OpenAndInitDB(context.Background(), dsn, "")
		if err == nil {
			db.Close()
			t.Fatalf("OpenAndInitDB(%q) should have been rejected", dsn)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("rejected DSNs still created files: %v", entries)
	}
}

func TestReaudit_ExistingPublicFileIsTightenedViaURI(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "legacy.db")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := OpenAndInitDB(context.Background(), "file:"+file+"?mode=rw", schemaForTests())
	if err != nil {
		t.Fatalf("OpenAndInitDB: %v", err)
	}
	defer db.Close()
	assertPrivate(t, file)
}

// A "file::memory:" PREFIX is not memory for SQLite: "file::memory:disk" is the
// relative file ":memory:disk". It must be treated (and protected) as a file.
func TestReaudit_MemoryPrefixIsAFile(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	t.Chdir(dir)
	for _, dsn := range []string{"file::memory:disk", "file::memory:disk2?mode=rwc"} {
		db, err := OpenAndInitDB(context.Background(), dsn, schemaAbs)
		if err != nil {
			t.Fatalf("OpenAndInitDB(%q): %v", dsn, err)
		}
		db.Close()
	}
	for _, name := range []string{":memory:disk", ":memory:disk2"} {
		assertPrivate(t, filepath.Join(dir, name))
		assertSchemaIn(t, filepath.Join(dir, name))
	}
}

// schemaAbs is resolved before any t.Chdir (schemaForTests is relative).
var schemaAbs, _ = filepath.Abs(schemaForTests())
