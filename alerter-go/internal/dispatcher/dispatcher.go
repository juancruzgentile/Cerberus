// Package dispatcher implements the concurrent, SSRF-hardened webhook alert
// dispatcher for Cerberus with exponential backoff, jitter, and a dead-letter queue.
package dispatcher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// MaxResponseBodyBytes limits how many bytes are read from a webhook response body.
	MaxResponseBodyBytes = 4096
	// MaxLastErrorChars matches the SQLite CHECK(length(last_error) <= 2048) constraint.
	MaxLastErrorChars = 2000
	// DefaultBatchSize is the maximum number of alerts fetched per polling cycle.
	DefaultBatchSize = 50
	// DefaultBaseBackoff is the base duration for exponential retry backoff.
	DefaultBaseBackoff = 2 * time.Second
	// DefaultMaxBackoff caps exponential retry backoff.
	DefaultMaxBackoff = 5 * time.Minute
)

// Config holds the runtime parameters for the Alert Dispatcher.
type Config struct {
	DBPath        string
	SchemaPath    string
	PollInterval  time.Duration
	Workers       int
	HTTPTimeout   time.Duration
	BatchSize     int
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
	AllowLoopback bool
	AllowPrivate  bool
	SigningSecret string
	Logger        *slog.Logger
}

// AlertJob represents a pending or failed alert delivery joined with its parent event.
type AlertJob struct {
	DeliveryID   int64
	EventID      int64
	TargetURL    string
	Status       string
	Attempts     int
	MaxAttempts  int
	NextRetryAt  int64
	Source       string
	Level        string
	Message      string
	MetadataJSON string
	CreatedAt    int64
	// LeaseUntil is the reservation deadline written by claimDueAlerts. It is
	// also the ownership token: final state updates only apply while
	// next_retry_at still equals this value.
	LeaseUntil int64
}

// WebhookPayload is the structured JSON body sent via HTTP POST to the target webhook URL.
type WebhookPayload struct {
	DeliveryID int64           `json:"delivery_id"`
	EventID    int64           `json:"event_id"`
	Source     string          `json:"source"`
	Level      string          `json:"level"`
	Message    string          `json:"message"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  int64           `json:"created_at"`
	Attempt    int             `json:"attempt"`
}

// Stats holds observability counters for alert_deliveries states.
type Stats struct {
	Pending int64 `json:"pending"`
	Sent    int64 `json:"sent"`
	Failed  int64 `json:"failed"`
	Dead    int64 `json:"dead"`
	Total   int64 `json:"total"`
}

// Dispatcher coordinates polling SQLite in WAL mode and dispatching webhooks across a worker pool.
type Dispatcher struct {
	cfg    Config
	db     *sql.DB
	client *http.Client
	logger *slog.Logger
	mu     sync.Mutex
}

// OpenAndInitDB opens the SQLite database using the pure-Go modernc.org/sqlite driver,
// applies mandatory Cerberus WAL and concurrency PRAGMAs, and optionally executes schema.sql.
func OpenAndInitDB(ctx context.Context, dbPath, schemaPath string) (*sql.DB, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("database path cannot be empty")
	}

	if err := ensurePrivateDBFile(dbPath); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	// Single connection pool serializes Go-side writes cleanly while WAL allows external concurrency.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("applying %q: %w", p, err)
		}
	}

	if strings.TrimSpace(schemaPath) != "" {
		schemaBytes, err := os.ReadFile(schemaPath)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("reading schema file %q: %w", schemaPath, err)
		}
		if _, err := db.ExecContext(ctx, string(schemaBytes)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("executing schema %q: %w", schemaPath, err)
		}
	}

	tightenCompanionFiles(dbPath)
	return db, nil
}

func isMemoryDB(path string) bool {
	return path == ":memory:" || strings.HasPrefix(path, "file::memory:") || strings.Contains(path, "mode=memory")
}

// ensurePrivateDBFile applies the common policy of the three heads: the
// database file is created (or fixed) with 0600 regardless of the umask.
func ensurePrivateDBFile(path string) error {
	if isMemoryDB(path) || strings.HasPrefix(path, "file:") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("creating database file %q: %w", path, err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("setting 0600 on %q: %w", path, err)
	}
	return nil
}

// tightenCompanionFiles sets 0600 on the WAL/SHM files if they exist.
func tightenCompanionFiles(path string) {
	if isMemoryDB(path) || strings.HasPrefix(path, "file:") {
		return
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Chmod(path+suffix, 0o600)
	}
}

// New creates a new Dispatcher with an SSRF-protected HTTP client.
func New(cfg Config, db *sql.DB) (*Dispatcher, error) {
	if db == nil {
		return nil, errors.New("database handle cannot be nil")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	d := &Dispatcher{
		cfg:    cfg,
		db:     db,
		logger: logger,
	}
	d.client = d.buildSafeHTTPClient()
	return d, nil
}

// buildSafeHTTPClient constructs an *http.Client that enforces connection-time IP filtering
// via net.Dialer.Control (preventing DNS rebinding and SSRF to metadata/unspecified ranges)
// and disables automatic HTTP redirects.
func (d *Dispatcher) buildSafeHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   d.cfg.HTTPTimeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("ssrf guard: invalid dial address %q: %w", address, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("ssrf guard: invalid IP %q: %w", host, err)
			}
			return ValidateResolvedIP(addr, d.cfg.AllowLoopback, d.cfg.AllowPrivate)
		},
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   d.cfg.HTTPTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   d.cfg.HTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("ssrf guard: HTTP redirects are disabled for webhook deliveries")
		},
	}
}

var (
	// Cloud metadata and special-purpose prefixes blocked unconditionally.
	prefixThisNetV4     = netip.MustParsePrefix("0.0.0.0/8")
	prefixLinkLocalV4   = netip.MustParsePrefix("169.254.0.0/16")
	prefixAlibabaMeta   = netip.MustParsePrefix("100.100.100.200/32")
	prefixAWSEC2MetaV6  = netip.MustParsePrefix("fd00:ec2::254/128")
	prefixNAT64WellKn   = netip.MustParsePrefix("64:ff9b::/96")
	prefixNAT64Local    = netip.MustParsePrefix("64:ff9b:1::/48")
	prefixReservedV4    = netip.MustParsePrefix("240.0.0.0/4")
	prefixCarrierGrade  = netip.MustParsePrefix("100.64.0.0/10")
	prefixBenchmarking  = netip.MustParsePrefix("198.18.0.0/15")
	prefixDocumentation = netip.MustParsePrefix("192.0.2.0/24")
)

// ValidateResolvedIP verifies that a resolved netip.Addr is safe to connect to at socket creation time.
func ValidateResolvedIP(addr netip.Addr, allowLoopback, allowPrivate bool) error {
	addr = addr.Unmap()

	if !addr.IsValid() {
		return errors.New("ssrf guard: invalid IP address")
	}
	if addr.IsUnspecified() || prefixThisNetV4.Contains(addr) {
		return fmt.Errorf("ssrf guard: unspecified or 'this-network' IP address %s is forbidden", addr)
	}
	if addr.IsMulticast() || prefixReservedV4.Contains(addr) {
		return fmt.Errorf("ssrf guard: multicast or reserved IP address %s is forbidden", addr)
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || prefixLinkLocalV4.Contains(addr) {
		return fmt.Errorf("ssrf guard: link-local / cloud metadata IP %s is forbidden", addr)
	}
	if prefixAlibabaMeta.Contains(addr) || prefixAWSEC2MetaV6.Contains(addr) {
		return fmt.Errorf("ssrf guard: cloud metadata endpoint IP %s is forbidden", addr)
	}
	if prefixNAT64WellKn.Contains(addr) || prefixNAT64Local.Contains(addr) {
		return fmt.Errorf("ssrf guard: NAT64 translated IPv6 address %s is forbidden", addr)
	}
	if addr == netip.MustParseAddr("255.255.255.255") {
		return fmt.Errorf("ssrf guard: broadcast IP %s is forbidden", addr)
	}

	if addr.IsLoopback() {
		if !allowLoopback {
			return fmt.Errorf("ssrf guard: loopback IP %s is disabled by configuration", addr)
		}
		return nil
	}

	if addr.IsPrivate() || prefixCarrierGrade.Contains(addr) || prefixBenchmarking.Contains(addr) || prefixDocumentation.Contains(addr) {
		if !allowPrivate {
			return fmt.Errorf("ssrf guard: private/internal IP %s is disabled by configuration", addr)
		}
	}

	return nil
}

// ValidateTargetURL performs strict pre-flight validation on a webhook target URL before dialing.
func ValidateTargetURL(rawURL string, allowLoopback, allowPrivate bool) (*url.URL, error) {
	if len(rawURL) < 10 || len(rawURL) > 1024 {
		return nil, errors.New("ssrf guard: URL length out of bounds [10, 1024]")
	}
	for i := 0; i < len(rawURL); i++ {
		b := rawURL[i]
		if b <= 0x20 || b == 0x7f {
			return nil, errors.New("ssrf guard: URL contains forbidden whitespace or ASCII control characters")
		}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ssrf guard: malformed URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("ssrf guard: unsupported scheme %q (only http and https allowed)", parsed.Scheme)
	}
	// Require exact lowercase scheme prefix to match SQLite CHECK constraint.
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, errors.New("ssrf guard: scheme must be lowercase http:// or https://")
	}

	if parsed.User != nil {
		return nil, errors.New("ssrf guard: embedded credentials in URL are forbidden")
	}

	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return nil, errors.New("ssrf guard: empty hostname in URL")
	}

	blockedHosts := map[string]struct{}{
		"metadata.google.internal": {},
		"metadata":                 {},
		"instance-data":            {},
		"0.0.0.0":                  {},
		"::":                       {},
	}
	if _, blocked := blockedHosts[host]; blocked {
		return nil, fmt.Errorf("ssrf guard: forbidden hostname %q", host)
	}
	if !allowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return nil, fmt.Errorf("ssrf guard: loopback hostname %q is disabled", host)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if err := ValidateResolvedIP(addr, allowLoopback, allowPrivate); err != nil {
			return nil, err
		}
	}

	return parsed, nil
}

// Run starts the continuous polling loop until ctx is canceled (Graceful Shutdown).
func (d *Dispatcher) Run(ctx context.Context) error {
	d.logger.Info("cerberus alerter-go started",
		"workers", d.cfg.Workers,
		"poll_interval", d.cfg.PollInterval.String(),
		"http_timeout", d.cfg.HTTPTimeout.String(),
		"allow_loopback", d.cfg.AllowLoopback,
	)

	// Process an immediate cycle on startup before waiting for the ticker.
	if _, err := d.ProcessBatch(ctx); err != nil && !errors.Is(err, context.Canceled) {
		d.logger.Error("initial batch error", "error", err)
	}

	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("cerberus alerter-go shutting down gracefully")
			return nil
		case <-ticker.C:
			if _, err := d.ProcessBatch(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				d.logger.Error("batch processing error", "error", err)
			}
		}
	}
}

// ProcessBatch queries due alerts from SQLite and dispatches them concurrently through a bounded worker pool.
// Returns the number of alerts processed in this cycle.
func (d *Dispatcher) ProcessBatch(ctx context.Context) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	jobs, err := d.claimDueAlerts(ctx, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	if len(jobs) == 0 {
		return 0, nil
	}

	workerCount := d.cfg.Workers
	if len(jobs) < workerCount {
		workerCount = len(jobs)
	}

	jobCh := make(chan AlertJob, len(jobs))
	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					return
				}
				d.processSingleAlert(ctx, job)
			}
		}()
	}

	wg.Wait()
	return len(jobs), nil
}

// leaseSeconds is how long a claimed batch stays reserved for this process.
// It covers the worst case of the whole batch (sequential rounds of HTTP
// timeouts across the worker pool) plus a safety margin.
func (d *Dispatcher) leaseSeconds() int64 {
	rounds := (d.cfg.BatchSize + d.cfg.Workers - 1) / d.cfg.Workers
	lease := time.Duration(rounds)*d.cfg.HTTPTimeout + 30*time.Second
	return int64(lease.Seconds())
}

// claimDueAlerts atomically reserves due alerts and returns them.
//
// A single UPDATE ... RETURNING (one SQLite write transaction) moves
// next_retry_at of every due row to now+lease. Any other alerter process
// (or goroutine) running the same statement no longer sees those rows as due,
// so two instances can never claim the same delivery at the same time.
// If this process dies, the lease expires and the delivery is retried.
func (d *Dispatcher) claimDueAlerts(ctx context.Context, nowUnix int64) ([]AlertJob, error) {
	leaseUntil := nowUnix + d.leaseSeconds()
	const claim = `
		UPDATE alert_deliveries
		SET next_retry_at = ?, updated_at = ?
		WHERE id IN (
			SELECT id FROM alert_deliveries
			WHERE status IN ('PENDING', 'FAILED')
			  AND attempts < max_attempts
			  AND next_retry_at <= ?
			ORDER BY next_retry_at ASC, id ASC
			LIMIT ?
		)
		RETURNING id;
	`
	rows, err := d.db.QueryContext(ctx, claim, leaseUntil, nowUnix, nowUnix, d.cfg.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("claiming due alerts: %w", err)
	}
	var ids []any
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning claimed id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterating claimed ids: %w", err)
	}
	rows.Close()
	if len(ids) == 0 {
		return nil, nil
	}

	query := `
		SELECT
			ad.id, ad.event_id, ad.target_url, ad.status, ad.attempts,
			ad.max_attempts, ad.next_retry_at,
			e.source, e.level, e.message, e.metadata_json, e.created_at
		FROM alert_deliveries AS ad
		INNER JOIN events AS e ON e.id = ad.event_id
		WHERE ad.next_retry_at = ? AND ad.id IN (?` + strings.Repeat(",?", len(ids)-1) + `)
		ORDER BY ad.id ASC;
	`
	args := append([]any{leaseUntil}, ids...)
	jrows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("loading claimed alerts: %w", err)
	}
	defer jrows.Close()

	var jobs []AlertJob
	for jrows.Next() {
		var j AlertJob
		if err := jrows.Scan(
			&j.DeliveryID,
			&j.EventID,
			&j.TargetURL,
			&j.Status,
			&j.Attempts,
			&j.MaxAttempts,
			&j.NextRetryAt,
			&j.Source,
			&j.Level,
			&j.Message,
			&j.MetadataJSON,
			&j.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning alert row: %w", err)
		}
		j.LeaseUntil = leaseUntil
		jobs = append(jobs, j)
	}
	if err := jrows.Err(); err != nil {
		return nil, fmt.Errorf("iterating alert rows: %w", err)
	}
	return jobs, nil
}

// processSingleAlert performs SSRF validation, executes the HTTP POST request, and updates SQLite state.
func (d *Dispatcher) processSingleAlert(ctx context.Context, job AlertJob) {
	attemptNum := job.Attempts + 1

	err := d.deliverWebhook(ctx, job, attemptNum)
	// Use a short non-canceled context to persist state transition even if shutdown was requested mid-flight.
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	nowUnix := time.Now().Unix()

	if err == nil {
		if dbErr := d.markSent(dbCtx, job, attemptNum, nowUnix); dbErr != nil {
			d.logger.Error("failed to mark alert SENT",
				"delivery_id", job.DeliveryID,
				"event_id", job.EventID,
				"error", dbErr,
			)
			return
		}
		d.logger.Info("alert delivered",
			"delivery_id", job.DeliveryID,
			"event_id", job.EventID,
			"attempt", attemptNum,
			"target_url", job.TargetURL,
		)
		return
	}

	newStatus := "FAILED"
	nextRetryAt := nowUnix
	if attemptNum >= job.MaxAttempts {
		newStatus = "DEAD"
	} else {
		backoff := CalculateBackoff(attemptNum, d.cfg.BaseBackoff, d.cfg.MaxBackoff)
		backoffSec := int64(backoff.Seconds())
		if backoffSec < 1 {
			backoffSec = 1
		}
		nextRetryAt = nowUnix + backoffSec
	}

	errMsg := truncateError(err.Error())
	if dbErr := d.markFailedOrDead(dbCtx, job, newStatus, attemptNum, nextRetryAt, errMsg, nowUnix); dbErr != nil {
		d.logger.Error("failed to update failed/dead alert state",
			"delivery_id", job.DeliveryID,
			"event_id", job.EventID,
			"error", dbErr,
		)
		return
	}

	d.logger.Warn("alert delivery failed",
		"delivery_id", job.DeliveryID,
		"event_id", job.EventID,
		"status", newStatus,
		"attempt", attemptNum,
		"max_attempts", job.MaxAttempts,
		"next_retry_at", nextRetryAt,
		"error", errMsg,
	)
}

// deliverWebhook validates the URL, serializes the JSON payload, signs it if configured, and checks HTTP 2xx.
func (d *Dispatcher) deliverWebhook(ctx context.Context, job AlertJob, attemptNum int) error {
	if _, err := ValidateTargetURL(job.TargetURL, d.cfg.AllowLoopback, d.cfg.AllowPrivate); err != nil {
		return err
	}

	rawMeta := json.RawMessage(job.MetadataJSON)
	if !json.Valid(rawMeta) {
		rawMeta = json.RawMessage(`{}`)
	}

	payload := WebhookPayload{
		DeliveryID: job.DeliveryID,
		EventID:    job.EventID,
		Source:     job.Source,
		Level:      job.Level,
		Message:    job.Message,
		Metadata:   rawMeta,
		CreatedAt:  job.CreatedAt,
		Attempt:    attemptNum,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, d.cfg.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, job.TargetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "Cerberus-Alerter/1.0")
	req.Header.Set("X-Cerberus-Event-ID", fmt.Sprintf("%d", job.EventID))
	req.Header.Set("X-Cerberus-Delivery-ID", fmt.Sprintf("%d", job.DeliveryID))
	req.Header.Set("X-Cerberus-Attempt", fmt.Sprintf("%d", attemptNum))
	// Stable across retries: receivers must use it to drop duplicates
	// (delivery is at-least-once, e.g. after a crash before markSent).
	req.Header.Set("Idempotency-Key", fmt.Sprintf("cerberus-delivery-%d", job.DeliveryID))

	if d.cfg.SigningSecret != "" {
		mac := hmac.New(sha256.New, []byte(d.cfg.SigningSecret))
		mac.Write(bodyBytes)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Cerberus-Signature-256", "sha256="+sig)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request error: %w", err)
	}
	defer resp.Body.Close()

	// Strictly bound response body reading to prevent memory exhaustion DoS from malicious servers.
	limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes))
	if readErr != nil {
		return fmt.Errorf("reading webhook response (status %d): %w", resp.StatusCode, readErr)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(limitedBody))
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		if snippet != "" {
			return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, snippet)
		}
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// errLeaseLost means another process re-claimed the delivery after our lease
// expired; the final state is then left to that owner.
var errLeaseLost = errors.New("lease lost: delivery re-claimed by another worker")

func (d *Dispatcher) markSent(ctx context.Context, job AlertJob, attempts int, nowUnix int64) error {
	const stmt = `
		UPDATE alert_deliveries
		SET status = 'SENT',
		    attempts = ?,
		    last_error = '',
		    updated_at = ?
		WHERE id = ? AND status IN ('PENDING', 'FAILED') AND next_retry_at = ?;
	`
	return checkOwned(d.db.ExecContext(ctx, stmt, attempts, nowUnix, job.DeliveryID, job.LeaseUntil))
}

func (d *Dispatcher) markFailedOrDead(
	ctx context.Context,
	job AlertJob,
	status string,
	attempts int,
	nextRetryAt int64,
	lastError string,
	nowUnix int64,
) error {
	const stmt = `
		UPDATE alert_deliveries
		SET status = ?,
		    attempts = ?,
		    next_retry_at = ?,
		    last_error = ?,
		    updated_at = ?
		WHERE id = ? AND status IN ('PENDING', 'FAILED') AND next_retry_at = ?;
	`
	return checkOwned(d.db.ExecContext(ctx, stmt, status, attempts, nextRetryAt, lastError, nowUnix, job.DeliveryID, job.LeaseUntil))
}

func checkOwned(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errLeaseLost
	}
	return nil
}

// GetStats returns the current count of alerts grouped by status (PENDING, SENT, FAILED, DEAD).
func (d *Dispatcher) GetStats(ctx context.Context) (Stats, error) {
	const query = `
		SELECT status, COUNT(*)
		FROM alert_deliveries
		GROUP BY status;
	`
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return Stats{}, fmt.Errorf("querying stats: %w", err)
	}
	defer rows.Close()

	var st Stats
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return Stats{}, fmt.Errorf("scanning stats: %w", err)
		}
		switch status {
		case "PENDING":
			st.Pending = count
		case "SENT":
			st.Sent = count
		case "FAILED":
			st.Failed = count
		case "DEAD":
			st.Dead = count
		}
		st.Total += count
	}
	if err := rows.Err(); err != nil {
		return Stats{}, err
	}
	return st, nil
}

// CalculateBackoff calculates baseBackoff * 2^(attempt-1) with small positive jitter, capped at maxBackoff.
func CalculateBackoff(attempt int, baseBackoff, maxBackoff time.Duration) time.Duration {
	if attempt <= 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 16 {
		shift = 16
	}
	backoff := baseBackoff * time.Duration(1<<shift)
	if backoff > maxBackoff || backoff <= 0 {
		backoff = maxBackoff
	}
	// Add up to 20% positive jitter so we never violate baseBackoff * 2^(attempt-1) lower bound.
	maxJitter := backoff / 5
	if maxJitter > 0 {
		backoff += time.Duration(rand.Int64N(int64(maxJitter)))
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return backoff
}

func truncateError(msg string) string {
	msg = strings.ToValidUTF8(msg, "?")
	runes := []rune(msg)
	if len(runes) > MaxLastErrorChars {
		runes = runes[:MaxLastErrorChars]
	}
	out := string(runes)
	if len(out) > MaxLastErrorChars {
		out = strings.ToValidUTF8(out[:MaxLastErrorChars], "")
	}
	return out
}
