package dispatcher

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSecurity_SSRFAndDNSRebindingGuard(t *testing.T) {
	// 1. Unconditionally forbidden IPs (even when allowLoopback=true and allowPrivate=true)
	unconditionalBlocked := []string{
		"169.254.169.254",
		"169.254.0.1",
		"100.100.100.200",
		"fd00:ec2::254",
		"::ffff:169.254.169.254",
		"::ffff:100.100.100.200",
		"0.0.0.0",
		"0.1.2.3",
		"::",
		"224.0.0.1",
		"239.255.255.250",
		"ff02::1",
		"255.255.255.255",
		"240.0.0.1",
		"64:ff9b::a9fe:a9fe",
		"64:ff9b:1::1",
		"fe80::1",
	}

	for _, rawIP := range unconditionalBlocked {
		addr := netip.MustParseAddr(rawIP)
		if err := ValidateResolvedIP(addr, true, true); err == nil {
			t.Errorf("expected IP %s to be unconditionally blocked, but it was allowed", rawIP)
		}
	}

	// 2. Private RFC1918 / CGNAT / ULA IPs must be blocked when AllowPrivate=false
	privateIPs := []string{
		"10.0.0.1",
		"10.255.255.254",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.0.1",
		"192.168.1.254",
		"::ffff:10.0.0.1",
		"::ffff:192.168.1.1",
		"100.64.0.1",
		"fc00::1",
		"fd12:3456:789a::1",
		"198.18.0.1",
		"192.0.2.1",
	}

	for _, rawIP := range privateIPs {
		addr := netip.MustParseAddr(rawIP)
		if err := ValidateResolvedIP(addr, true, false); err == nil {
			t.Errorf("expected private IP %s to be blocked when allowPrivate=false", rawIP)
		}
		if err := ValidateResolvedIP(addr, true, true); err != nil {
			t.Errorf("expected private IP %s to be allowed when allowPrivate=true, got: %v", rawIP, err)
		}
	}

	// 3. Loopback IPs must be blocked when AllowLoopback=false
	loopbackIPs := []string{
		"127.0.0.1",
		"127.0.1.1",
		"127.255.255.254",
		"::1",
		"::ffff:127.0.0.1",
	}

	for _, rawIP := range loopbackIPs {
		addr := netip.MustParseAddr(rawIP)
		if err := ValidateResolvedIP(addr, false, true); err == nil {
			t.Errorf("expected loopback IP %s to be blocked when allowLoopback=false", rawIP)
		}
		if err := ValidateResolvedIP(addr, true, true); err != nil {
			t.Errorf("expected loopback IP %s to be allowed when allowLoopback=true, got: %v", rawIP, err)
		}
	}
}

func TestSecurity_DialerControlBlocksDNSRebindingAtSocketLevel(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "rebinding.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	var targetReached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Configure Dispatcher with AllowLoopback=false.
	// Even if a request attempts to dial 127.0.0.1, both ValidateTargetURL and net.Dialer.Control block it.
	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       2,
		HTTPTimeout:   1 * time.Second,
		AllowLoopback: false,
		AllowPrivate:  false,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test the underlying SSRF-protected http.Client directly against srv.URL (which binds to 127.0.0.1)
	// to prove net.Dialer.Control physically aborts the TCP socket before handshake even if ValidateTargetURL is bypassed!
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	_, dialErr := disp.client.Do(req)
	if dialErr == nil {
		t.Fatalf("expected net.Dialer.Control to block TCP connection to loopback when AllowLoopback=false")
	}
	if !strings.Contains(dialErr.Error(), "ssrf guard") {
		t.Fatalf("expected ssrf guard error from Dialer.Control, got: %v", dialErr)
	}
	if targetReached.Load() {
		t.Fatalf("SSRF breach: target server received a connection despite Dialer.Control guard!")
	}
}

func TestSecurity_OpenRedirectBlockedAllStatusCodes(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "redirects.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	var secondaryHits atomic.Int32
	var servedMu sync.Mutex
	servedCodes := map[int]bool{}
	redirectCodes := []int{
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal-secret":
			secondaryHits.Add(1)
			w.WriteHeader(http.StatusOK)
		case "/redirect-meta":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
		default:
			// The code is sent as a number (e.g. ?code=308); an unknown value
			// is a test bug, so answer 400 instead of silently using 302.
			code, err := strconv.Atoi(r.URL.Query().Get("code"))
			if err != nil || code < 300 || code > 399 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			servedMu.Lock()
			servedCodes[code] = true
			servedMu.Unlock()
			http.Redirect(w, r, "/internal-secret", code)
		}
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"sec-scanner", "CRITICAL", "Open redirect test", `{}`,
	)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	eventID, _ := res.LastInsertId()
	now := time.Now().Unix() - 10

	// Insert redirect to AWS metadata + redirects for 301/302/303/307/308
	_, err = db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
		eventID, srv.URL+"/redirect-meta", now,
	)
	if err != nil {
		t.Fatalf("insert redirect-meta: %v", err)
	}

	for _, c := range redirectCodes {
		_, err = db.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
			eventID, srv.URL+"/bounce?code="+strconv.Itoa(c), now,
		)
		if err != nil {
			t.Fatalf("insert bounce %d: %v", c, err)
		}
	}

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       4,
		HTTPTimeout:   2 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("New dispatcher: %v", err)
	}

	processed, err := disp.ProcessBatch(ctx)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if processed != 1+len(redirectCodes) {
		t.Fatalf("expected %d processed, got %d", 1+len(redirectCodes), processed)
	}
	if secondaryHits.Load() != 0 {
		t.Fatalf("SSRF Open Redirect breach: client followed redirect %d times!", secondaryHits.Load())
	}

	// Prove that every advertised redirect code was really exercised.
	for _, c := range redirectCodes {
		if !servedCodes[c] {
			t.Fatalf("redirect code %d was never served by the test server", c)
		}
	}

	st, err := disp.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if st.Dead != int64(1+len(redirectCodes)) || st.Sent != 0 {
		t.Fatalf("expected all redirect deliveries to be marked DEAD, got stats: %+v", st)
	}
}

func TestSecurity_ResponseBodyBombAndTarPitTimeout(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dos.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bomb-500":
			// Respond with HTTP 500 and stream 10MB of multi-byte / invalid UTF-8 garbage
			w.WriteHeader(http.StatusInternalServerError)
			chunk := strings.Repeat("🔥\xff\xfeA", 4096) // ~28KB per chunk
			for i := 0; i < 350; i++ {
				if _, err := w.Write([]byte(chunk)); err != nil {
					return
				}
			}
		case "/bomb-200":
			// Respond with HTTP 200 and stream 10MB of garbage
			w.WriteHeader(http.StatusOK)
			chunk := strings.Repeat("X", 65536)
			for i := 0; i < 160; i++ {
				if _, err := w.Write([]byte(chunk)); err != nil {
					return
				}
			}
		case "/tarpit":
			// Slowloris / Tar Pit: sleep longer than client timeout
			time.Sleep(600 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		"dos-sensor", "ERROR", "Testing DoS resilience", `{}`,
	)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	eventID, _ := res.LastInsertId()
	now := time.Now().Unix() - 5

	for _, path := range []string{"/bomb-500", "/bomb-200", "/tarpit"} {
		_, err = db.ExecContext(ctx,
			`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
			eventID, srv.URL+path, now,
		)
		if err != nil {
			t.Fatalf("insert delivery %s: %v", path, err)
		}
	}

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       3,
		HTTPTimeout:   150 * time.Millisecond,
		AllowLoopback: true,
		AllowPrivate:  true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("New dispatcher: %v", err)
	}

	start := time.Now()
	processed, err := disp.ProcessBatch(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if processed != 3 {
		t.Fatalf("expected 3 deliveries processed, got %d", processed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("batch took too long (%v), timeout protection failed", elapsed)
	}

	// Verify last_error constraints and UTF-8 validity in SQLite
	rows, err := db.QueryContext(ctx, `SELECT target_url, status, last_error FROM alert_deliveries`)
	if err != nil {
		t.Fatalf("querying deliveries: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u, st, lastErr string
		if err := rows.Scan(&u, &st, &lastErr); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(lastErr) > MaxLastErrorChars {
			t.Errorf("last_error length %d exceeds MaxLastErrorChars %d", len(lastErr), MaxLastErrorChars)
		}
		if !utf8.ValidString(lastErr) {
			t.Errorf("last_error contains invalid UTF-8 for %s", u)
		}
		if strings.HasSuffix(u, "/tarpit") && st != "DEAD" {
			t.Errorf("expected /tarpit delivery to time out and become DEAD, got %s", st)
		}
		if strings.HasSuffix(u, "/bomb-500") && st != "DEAD" {
			t.Errorf("expected /bomb-500 delivery to become DEAD, got %s", st)
		}
	}
}

func TestSecurity_SQLInjectionAndTruncateErrorBounds(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sqli.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return an error payload containing SQL injection quotes and 5000 multi-byte characters
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`'); DROP TABLE alert_deliveries; -- ` + strings.Repeat("⚡", 1500)))
	}))
	defer srv.Close()

	sqliSource := `sensor'); DELETE FROM events; --`
	sqliMsg := `Alert '); UPDATE alert_deliveries SET status='SENT'; --`
	res, err := db.ExecContext(ctx,
		`INSERT INTO events (source, level, message, metadata_json) VALUES (?, ?, ?, ?)`,
		sqliSource, "CRITICAL", sqliMsg, `{"inject":"' OR 1=1 --"}`,
	)
	if err != nil {
		t.Fatalf("insert sqli event: %v", err)
	}
	eventID, _ := res.LastInsertId()

	_, err = db.ExecContext(ctx,
		`INSERT INTO alert_deliveries (event_id, target_url, max_attempts, next_retry_at) VALUES (?, ?, 1, ?)`,
		eventID, srv.URL+"/sqli", time.Now().Unix()-1,
	)
	if err != nil {
		t.Fatalf("insert delivery: %v", err)
	}

	disp, err := New(Config{
		DBPath:        dbPath,
		Workers:       1,
		HTTPTimeout:   2 * time.Second,
		AllowLoopback: true,
		AllowPrivate:  true,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db)
	if err != nil {
		t.Fatalf("New dispatcher: %v", err)
	}

	if _, err := disp.ProcessBatch(ctx); err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	st, err := disp.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats failed after SQLi payload: %v", err)
	}
	if st.Dead != 1 || st.Total != 1 {
		t.Fatalf("expected 1 DEAD delivery intact in table, got %+v", st)
	}

	// Verify truncateError directly with boundary multi-byte UTF-8 string
	hugeMultiByte := strings.Repeat("🔥", 2500) // 10,000 bytes, 2,500 runes
	truncated := truncateError(hugeMultiByte)
	if len(truncated) > MaxLastErrorChars {
		t.Fatalf("expected truncated byte length <= %d, got %d", MaxLastErrorChars, len(truncated))
	}
	if !utf8.ValidString(truncated) {
		t.Fatalf("expected truncated string to be valid UTF-8")
	}
}
