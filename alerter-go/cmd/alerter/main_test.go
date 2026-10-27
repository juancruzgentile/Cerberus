package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juancruzgentile/cerberus/alerter-go/internal/dispatcher"
)

func TestMetricsServerSecurityAndTimeouts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "metrics_test.db")
	schemaPath := filepath.Join("..", "..", "..", "schema", "schema.sql")

	db, err := dispatcher.OpenAndInitDB(ctx, dbPath, schemaPath)
	if err != nil {
		t.Fatalf("OpenAndInitDB failed: %v", err)
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	disp, err := dispatcher.New(dispatcher.Config{
		DBPath: dbPath,
		Logger: logger,
	}, db)
	if err != nil {
		t.Fatalf("dispatcher.New failed: %v", err)
	}

	srv, err := startMetricsServer(ctx, "127.0.0.1:0", disp, logger)
	if err != nil {
		t.Fatalf("startMetricsServer failed: %v", err)
	}
	defer shutdownMetrics(srv)

	// Verify Slowloris protection timeouts are strictly configured on http.Server
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("http.Server missing mandatory Slowloris timeouts: %+v", srv)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Fatalf("http.Server missing MaxHeaderBytes limit")
	}

	// Test handler directly for method enforcement (only GET is allowed)
	for _, endpoint := range []string{"/health", "/stats"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
			req, _ := http.NewRequestWithContext(ctx, method, "http://127.0.0.1"+endpoint, strings.NewReader(`{}`))
			rec := &responseRecorder{header: make(http.Header)}
			srv.Handler.ServeHTTP(rec, req)
			if rec.code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 Method Not Allowed for %s %s, got %d", method, endpoint, rec.code)
			}
			if rec.header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("expected X-Content-Type-Options: nosniff on %s", endpoint)
			}
		}

		// Verify GET succeeds
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1"+endpoint, nil)
		rec := &responseRecorder{header: make(http.Header)}
		srv.Handler.ServeHTTP(rec, req)
		if rec.code != http.StatusOK {
			t.Errorf("expected 200 OK for GET %s, got %d", endpoint, rec.code)
		}
	}

	// Ensure shutdown completes quickly
	done := make(chan struct{})
	go func() {
		shutdownMetrics(srv)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("shutdownMetrics timed out")
	}
}

type responseRecorder struct {
	header http.Header
	body   strings.Builder
	code   int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}
