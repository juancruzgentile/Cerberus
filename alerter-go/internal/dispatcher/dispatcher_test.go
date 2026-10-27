package dispatcher

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateTargetURLAndIP(t *testing.T) {
	blockedURLs := []string{
		"ftp://example.com/webhook",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_INFO",
		"HTTP://example.com/uppercase",
		"https://user:pass@example.com/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://0.0.0.0:8080/hook",
		"http://[::]:8080/hook",
		"http://224.0.0.1/multicast",
		"http://example.com/space in url",
		"http://example.com/crlf\r\ninjection",
		"http://example.com/null\x00byte",
		"http://0.1.2.3:8080/this-net",
		"http://[64:ff9b::169.254.169.254]/nat64-meta",
		"http://a",
	}

	for _, u := range blockedURLs {
		if _, err := ValidateTargetURL(u, true, true); err == nil {
			t.Errorf("expected URL %q to be blocked by SSRF validator, but it passed", u)
		}
	}

	// Loopback blocked when AllowLoopback=false
	if _, err := ValidateTargetURL("http://127.0.0.1:8080/hook", false, true); err == nil {
		t.Errorf("expected 127.0.0.1 to be blocked when AllowLoopback=false")
	}
	if _, err := ValidateTargetURL("http://localhost:8080/hook", false, true); err == nil {
		t.Errorf("expected localhost to be blocked when AllowLoopback=false")
	}

	// Private IP blocked when AllowPrivate=false
	if _, err := ValidateTargetURL("http://10.0.0.1:8080/hook", true, false); err == nil {
		t.Errorf("expected 10.0.0.1 to be blocked when AllowPrivate=false")
	}

	// Loopback allowed when AllowLoopback=true
	if _, err := ValidateTargetURL("http://127.0.0.1:8080/hook", true, true); err != nil {
		t.Errorf("expected 127.0.0.1 to be allowed when AllowLoopback=true, got: %v", err)
	}

	// Cloud metadata IPv4-mapped IPv6 must also be blocked
	mappedMeta := netip.MustParseAddr("::ffff:169.254.169.254")
	if err := ValidateResolvedIP(mappedMeta, true, true); err == nil {
		t.Errorf("expected IPv4-mapped IPv6 metadata address to be blocked")
	}
}

func TestSuccessfulDeliveryHeadersAndHMAC(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_success.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	const secret = "cerberus-hmac-secret-key"

	type capturedReq struct {
		headers http.Header
		rawBody []byte
		payload WebhookPayload
	}
	var mu sync.Mutex
	captured := make(map[string]capturedReq)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p WebhookPayload
		_ = json.Unmarshal(body, &p)

		mu.Lock()
		captured[r.URL.Path] = capturedReq{
			headers: r.Header.Clone(),
			rawBody: body,
			payload: p,
		}
		mu.Unlock()

		if r.URL.Path == "/accepted" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"ids-sensor-01", "CRITICAL", "Unauthorized root login attempt", `{"ip":"198.51.100.77"}`,
	)
	if err != nil {
		t.Fatalf("inserting event: %v", err)
	}
	eventID, _ := res.LastInsertId()

	now := time.Now().Unix() - 5
	res1, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
		eventID, srv.URL+"/ok", now,
	)
	if err != nil {
		t.Fatalf("inserting /ok delivery: %v", err)
	}
	delivID1, _ := res1.LastInsertId()

	res2, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
		eventID, srv.URL+"/accepted", now,
	)
	if err != nil {
		t.Fatalf("inserting /accepted delivery: %v", err)
	}
	delivID2, _ := res2.LastInsertId()

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       2,
		HTTPTimeout:   2 * time.Second,
		BaseBackoff:   2 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		SigningSecret: secret,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("creating dispatcher: %v", err)
	}

	processed, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if processed != 2 {
		t.Fatalf("expected 2 alerts processed, got %d", processed)
	}

	for path, expectedDelivID := range map[string]int64{"/ok": delivID1, "/accepted": delivID2} {
		mu.Lock()
		capReq, ok := captured[path]
		mu.Unlock()
		if !ok {
			t.Fatalf("webhook %s was not called", path)
		}

		// Verify X-Cerberus-* headers
		if got := capReq.headers.Get("X-Cerberus-Event-ID"); got != fmt.Sprintf("%d", eventID) {
			t.Errorf("%s: expected X-Cerberus-Event-ID=%d, got %q", path, eventID, got)
		}
		if got := capReq.headers.Get("X-Cerberus-Delivery-ID"); got != fmt.Sprintf("%d", expectedDelivID) {
			t.Errorf("%s: expected X-Cerberus-Delivery-ID=%d, got %q", path, expectedDelivID, got)
		}
		if got := capReq.headers.Get("X-Cerberus-Attempt"); got != "1" {
			t.Errorf("%s: expected X-Cerberus-Attempt=1, got %q", path, got)
		}

		// Verify HMAC-SHA256 signature
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(capReq.rawBody)
		expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := capReq.headers.Get("X-Cerberus-Signature-256"); got != expectedSig {
			t.Errorf("%s: HMAC mismatch: expected %q, got %q", path, expectedSig, got)
		}

		// Verify JSON payload fields
		if capReq.payload.DeliveryID != expectedDelivID ||
			capReq.payload.EventID != eventID ||
			capReq.payload.Source != "ids-sensor-01" ||
			capReq.payload.Level != "CRITICAL" ||
			capReq.payload.Message != "Unauthorized root login attempt" ||
			capReq.payload.Attempt != 1 {
			t.Errorf("%s: unexpected payload: %+v", path, capReq.payload)
		}

		// Verify database state: status='SENT', attempts=1, last_error=''
		var status, lastErr string
		var attempts int
		err := db.QueryRowContext(ctx,
			`SELECT status, attempts, last_error FROM alert_deliveries WHERE id = ?`, expectedDelivID,
		).Scan(&status, &attempts, &lastErr)
		if err != nil {
			t.Fatalf("querying delivery %d: %v", expectedDelivID, err)
		}
		if status != "SENT" || attempts != 1 || lastErr != "" {
			t.Errorf("delivery %d: expected status=SENT, attempts=1, last_error='', got status=%q, attempts=%d, last_error=%q",
				expectedDelivID, status, attempts, lastErr)
		}
	}
}

func TestTransientFailureAndSubsequentRecovery(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_retry_recovery.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	var flakyAttempts atomic.Int32
	var timeoutAttempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky-500":
			n := flakyAttempts.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`database down temporarily`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"recovered":true}`))
		case "/flaky-timeout":
			n := timeoutAttempts.Add(1)
			if n == 1 {
				time.Sleep(250 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"firewall-01", "ERROR", "Upstream connection reset", `{}`,
	)
	if err != nil {
		t.Fatalf("inserting event: %v", err)
	}
	eventID, _ := res.LastInsertId()

	now := time.Now().Unix() - 2
	res500, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
		eventID, srv.URL+"/flaky-500", now,
	)
	if err != nil {
		t.Fatalf("inserting flaky-500 delivery: %v", err)
	}
	id500, _ := res500.LastInsertId()

	resTimeout, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
		eventID, srv.URL+"/flaky-timeout", now,
	)
	if err != nil {
		t.Fatalf("inserting flaky-timeout delivery: %v", err)
	}
	idTimeout, _ := resTimeout.LastInsertId()

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       2,
		HTTPTimeout:   100 * time.Millisecond,
		BaseBackoff:   5 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("creating dispatcher: %v", err)
	}

	// Attempt 1: Both should fail transiently -> status='FAILED', attempts=1, next_retry_at > now
	beforeBatch := time.Now().Unix()
	n1, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch 1 failed: %v", err)
	}
	if n1 != 2 {
		t.Fatalf("expected 2 alerts processed in batch 1, got %d", n1)
	}

	for _, id := range []int64{id500, idTimeout} {
		var status, lastErr string
		var attempts int
		var nextRetry int64
		err := db.QueryRowContext(ctx,
			`SELECT status, attempts, next_retry_at, last_error FROM alert_deliveries WHERE id = ?`, id,
		).Scan(&status, &attempts, &nextRetry, &lastErr)
		if err != nil {
			t.Fatalf("querying delivery %d: %v", id, err)
		}
		if status != "FAILED" {
			t.Errorf("delivery %d: expected status='FAILED', got %q", id, status)
		}
		if attempts != 1 {
			t.Errorf("delivery %d: expected attempts=1, got %d", id, attempts)
		}
		if nextRetry <= beforeBatch {
			t.Errorf("delivery %d: expected next_retry_at (%d) > now (%d)", id, nextRetry, beforeBatch)
		}
		if lastErr == "" {
			t.Errorf("delivery %d: expected non-empty last_error on FAILED status", id)
		}
	}

	// Immediate poll before next_retry_at arrives must process 0 alerts
	nMid, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch mid failed: %v", err)
	}
	if nMid != 0 {
		t.Fatalf("expected 0 due alerts before next_retry_at window, got %d", nMid)
	}

	// Fast-forward next_retry_at to simulate retry window arrival
	_, err = db.ExecContext(ctx, `UPDATE alert_deliveries SET next_retry_at = ? WHERE status = 'FAILED'`, time.Now().Unix()-1)
	if err != nil {
		t.Fatalf("fast-forwarding next_retry_at: %v", err)
	}

	// Attempt 2: Both should now succeed -> status='SENT', attempts=2, last_error=''
	n2, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch 2 failed: %v", err)
	}
	if n2 != 2 {
		t.Fatalf("expected 2 alerts processed in batch 2, got %d", n2)
	}

	for _, id := range []int64{id500, idTimeout} {
		var status, lastErr string
		var attempts int
		err := db.QueryRowContext(ctx,
			`SELECT status, attempts, last_error FROM alert_deliveries WHERE id = ?`, id,
		).Scan(&status, &attempts, &lastErr)
		if err != nil {
			t.Fatalf("querying delivery %d after recovery: %v", id, err)
		}
		if status != "SENT" || attempts != 2 || lastErr != "" {
			t.Errorf("delivery %d after recovery: expected status=SENT, attempts=2, last_error='', got status=%q, attempts=%d, last_error=%q",
				id, status, attempts, lastErr)
		}
	}
}

func TestExhaustedRetriesTransitionToDeadAndIgnoredByProcessBatch(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_dlq.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	var failHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		failHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`permanent upstream failure`))
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"ids-sensor-02", "CRITICAL", "Kernel module tampering", `{}`,
	)
	if err != nil {
		t.Fatalf("inserting event: %v", err)
	}
	eventID, _ := res.LastInsertId()

	now := time.Now().Unix() - 5
	// Alert 1: max_attempts = 2 (Attempt 1 -> FAILED, Attempt 2 -> DEAD)
	resFail, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 2, ?)`,
		eventID, srv.URL+"/always-fail", now,
	)
	if err != nil {
		t.Fatalf("inserting always-fail delivery: %v", err)
	}
	failID, _ := resFail.LastInsertId()

	// Alert 2: Redirect SSRF guard with max_attempts = 1 -> immediate DEAD
	resRedir, err := db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
		eventID, srv.URL+"/redirect", now,
	)
	if err != nil {
		t.Fatalf("inserting redirect delivery: %v", err)
	}
	redirID, _ := resRedir.LastInsertId()

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       2,
		HTTPTimeout:   2 * time.Second,
		BaseBackoff:   2 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("creating dispatcher: %v", err)
	}

	// Cycle 1
	n1, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch 1 failed: %v", err)
	}
	if n1 != 2 {
		t.Fatalf("expected 2 alerts processed in cycle 1, got %d", n1)
	}

	// Fast-forward next_retry_at for the FAILED alert
	_, err = db.ExecContext(ctx, `UPDATE alert_deliveries SET next_retry_at = ? WHERE id = ?`, time.Now().Unix()-1, failID)
	if err != nil {
		t.Fatalf("fast-forwarding retry: %v", err)
	}

	// Cycle 2: failID hits attempt 2 == max_attempts (2) -> transitions to DEAD
	n2, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch 2 failed: %v", err)
	}
	if n2 != 1 {
		t.Fatalf("expected 1 alert processed in cycle 2, got %d", n2)
	}

	for _, id := range []int64{failID, redirID} {
		var status string
		var attempts, maxAttempts int
		err := db.QueryRowContext(ctx,
			`SELECT status, attempts, max_attempts FROM alert_deliveries WHERE id = ?`, id,
		).Scan(&status, &attempts, &maxAttempts)
		if err != nil {
			t.Fatalf("querying delivery %d: %v", id, err)
		}
		if status != "DEAD" || attempts != maxAttempts {
			t.Errorf("delivery %d: expected status=DEAD and attempts=%d, got status=%q, attempts=%d",
				id, maxAttempts, status, attempts)
		}
	}

	// Even if next_retry_at is in the past, ProcessBatch must NEVER re-process DEAD alerts
	_, err = db.ExecContext(ctx, `UPDATE alert_deliveries SET next_retry_at = 0 WHERE status = 'DEAD'`)
	if err != nil {
		t.Fatalf("updating next_retry_at on DEAD alerts: %v", err)
	}

	hitsBefore := failHits.Load()
	n3, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch 3 failed: %v", err)
	}
	if n3 != 0 {
		t.Fatalf("expected 0 DEAD alerts processed by ProcessBatch, got %d", n3)
	}
	if failHits.Load() != hitsBefore {
		t.Fatalf("expected no additional HTTP hits for DEAD alerts")
	}
}

func TestWorkerPoolConcurrencyAndStatsObservability(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrency.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	var totalDeliveries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			totalDeliveries.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/fail":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`busy`))
		}
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"load-generator", "WARN", "High concurrency burst test", `{"burst":20}`,
	)
	if err != nil {
		t.Fatalf("inserting event: %v", err)
	}
	eventID, _ := res.LastInsertId()

	now := time.Now().Unix() - 5
	const concurrentOK = 20

	// Insert 20 due alerts to be dispatched concurrently by the worker pool
	for i := 0; i < concurrentOK; i++ {
		_, err := db.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
			eventID, srv.URL+"/ok", now,
		)
		if err != nil {
			t.Fatalf("inserting concurrent ok alert %d: %v", i, err)
		}
	}

	// Also insert 2 alerts destined for FAILED (max_attempts=3), 1 for DEAD (max_attempts=1),
	// and 3 PENDING in the future (next_retry_at > now) to verify all GetStats counters.
	for i := 0; i < 2; i++ {
		_, err := db.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
			eventID, srv.URL+"/fail", now,
		)
		if err != nil {
			t.Fatalf("inserting fail alert: %v", err)
		}
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
		eventID, srv.URL+"/fail", now,
	)
	if err != nil {
		t.Fatalf("inserting dead alert: %v", err)
	}
	futureRetry := time.Now().Unix() + 3600
	for i := 0; i < 3; i++ {
		_, err := db.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 3, ?)`,
			eventID, srv.URL+"/ok", futureRetry,
		)
		if err != nil {
			t.Fatalf("inserting future pending alert: %v", err)
		}
	}

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       8,
		BatchSize:     50,
		HTTPTimeout:   3 * time.Second,
		BaseBackoff:   10 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		SigningSecret: "concurrent-secret",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("creating dispatcher: %v", err)
	}

	// Verify initial stats before processing
	stInit, err := disp.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats initial failed: %v", err)
	}
	if stInit.Pending != 26 || stInit.Sent != 0 || stInit.Failed != 0 || stInit.Dead != 0 || stInit.Total != 26 {
		t.Fatalf("unexpected initial stats: %+v", stInit)
	}

	// Run concurrent callers to ProcessBatch + GetStats to verify thread-safety under -race
	var wg sync.WaitGroup
	wg.Add(3)
	var processedTotal atomic.Int32
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			n, err := disp.ProcessBatch(ctx)
			if err != nil {
				t.Errorf("concurrent ProcessBatch error: %v", err)
			}
			processedTotal.Add(int32(n))
		}()
	}
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if _, err := disp.GetStats(ctx); err != nil {
				t.Errorf("concurrent GetStats error: %v", err)
			}
		}
	}()
	wg.Wait()

	if processedTotal.Load() != 23 {
		t.Fatalf("expected 23 due alerts processed across concurrent batch calls, got %d", processedTotal.Load())
	}
	if totalDeliveries.Load() != concurrentOK {
		t.Fatalf("expected %d successful webhook deliveries, got %d", concurrentOK, totalDeliveries.Load())
	}

	stFinal, err := disp.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats final failed: %v", err)
	}
	if stFinal.Pending != 3 || stFinal.Sent != 20 || stFinal.Failed != 2 || stFinal.Dead != 1 || stFinal.Total != 26 {
		t.Fatalf("unexpected final stats (expected Pending=3, Sent=20, Failed=2, Dead=1, Total=26): %+v", stFinal)
	}
}
