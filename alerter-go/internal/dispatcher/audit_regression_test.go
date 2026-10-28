package dispatcher

// Regression tests for the issues reported in the audit of commit fac6998.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Two independent alerter instances (separate DB handles, like two processes)
// poll the same database at the same time: every delivery must be sent once.
func TestAudit_TwoInstancesNeverDeliverTwice(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "multi.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	var mu sync.Mutex
	hits := map[string]int{}
	idemKeys := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond) // widen the race window
		mu.Lock()
		hits[r.Header.Get("X-Cerberus-Delivery-ID")]++
		idemKeys[r.Header.Get("Idempotency-Key")] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	setup, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB: %v", err)
	}
	res, err := setup.ExecContext(ctx,
		`INSERT INTO events (source, level, message) VALUES ('svc', 'CRITICAL', 'boom')`)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	eventID, _ := res.LastInsertId()
	const deliveries = 40
	for i := 0; i < deliveries; i++ {
		if _, err := setup.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, next_retry_at) VALUES (?, ?, 0)`,
			eventID, srv.URL+"/hook"); err != nil {
			t.Fatalf("insert delivery: %v", err)
		}
	}
	_ = setup.Close()

	newInstance := func() *Dispatcher {
		db, err := OpenAndInitDB(ctx, dbPath, "")
		if err != nil {
			t.Fatalf("OpenAndInitDB: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		d, err := New(Config{
			DBPath:        dbPath,
			Workers:       4,
			BatchSize:     deliveries,
			HTTPTimeout:   2 * time.Second,
			AllowLoopback: true,
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		}, db)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return d
	}
	a, b := newInstance(), newInstance()

	var wg sync.WaitGroup
	for _, d := range []*Dispatcher{a, b} {
		wg.Add(1)
		go func(d *Dispatcher) {
			defer wg.Done()
			if _, err := d.ProcessBatch(ctx); err != nil {
				t.Errorf("ProcessBatch: %v", err)
			}
		}(d)
	}
	wg.Wait()

	if len(hits) != deliveries {
		t.Fatalf("expected %d distinct deliveries, got %d", deliveries, len(hits))
	}
	for id, n := range hits {
		if n != 1 {
			t.Fatalf("delivery %s was sent %d times (duplicate)", id, n)
		}
	}
	if len(idemKeys) != deliveries || idemKeys[""] {
		t.Fatalf("every request must carry a distinct Idempotency-Key, got %v", idemKeys)
	}
	st, err := a.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if st.Sent != deliveries {
		t.Fatalf("expected %d SENT, got %+v", deliveries, st)
	}
}

// A worker whose lease was taken over must not overwrite the new owner's state.
func TestAudit_LostLeaseDoesNotOverwriteState(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "lease.db")
	db, err := OpenAndInitDB(ctx, dbPath, filepath.Join("..", "..", "..", "schema", "schema.sql"))
	if err != nil {
		t.Fatalf("OpenAndInitDB: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `INSERT INTO events (source, level, message) VALUES ('s','ERROR','m')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, next_retry_at) VALUES (1, 'http://127.0.0.1:1/x', 0)`); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{DBPath: dbPath, AllowLoopback: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, db)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := d.claimDueAlerts(ctx, time.Now().Unix())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v %d", err, len(jobs))
	}
	// Simulate another instance re-claiming after expiry (new lease value).
	if _, err := db.ExecContext(ctx, `UPDATE alert_deliveries SET next_retry_at = next_retry_at + 1000`); err != nil {
		t.Fatal(err)
	}
	if err := d.markSent(ctx, jobs[0], 1, time.Now().Unix()); err != errLeaseLost {
		t.Fatalf("expected errLeaseLost, got %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM alert_deliveries WHERE id = 1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("state was overwritten by stale owner: %s", status)
	}
}

// With a permissive umask (022) the database must still be created as 0600.
func TestAudit_NewDatabaseIsPrivate(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	dbPath := filepath.Join(t.TempDir(), "perm.db")
	db, err := OpenAndInitDB(context.Background(), dbPath, filepath.Join("..", "..", "..", "schema", "schema.sql"))
	if err != nil {
		t.Fatalf("OpenAndInitDB: %v", err)
	}
	defer db.Close()
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s has mode %o, want 600", filepath.Base(p), perm)
		}
	}
}
