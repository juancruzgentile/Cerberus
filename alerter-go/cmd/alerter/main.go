// Command alerter runs the Cerberus Head 2 concurrent webhook alert dispatcher.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/juancruzgentile/cerberus/alerter-go/internal/dispatcher"
)

func main() {
	var (
		dbPath        = flag.String("db", "cerberus.db", "Path to the shared SQLite database")
		schemaPath    = flag.String("schema", "", "Optional path to schema.sql to initialize tables")
		pollInterval  = flag.Duration("poll-interval", 1*time.Second, "Polling interval for due alerts")
		workers       = flag.Int("workers", 4, "Number of concurrent webhook delivery workers")
		httpTimeout   = flag.Duration("timeout", 5*time.Second, "Per-request HTTP webhook timeout")
		baseBackoff   = flag.Duration("base-backoff", 2*time.Second, "Base duration for exponential backoff")
		batchSize     = flag.Int("batch-size", 50, "Maximum alerts fetched per polling cycle")
		once          = flag.Bool("once", false, "Process a single batch of due alerts and exit")
		allowLoopback = flag.Bool("allow-loopback", envBoolOrDefault("CERBERUS_ALLOW_LOOPBACK", false), "Allow webhook delivery to loopback addresses (127.0.0.1/::1)")
		allowPrivate  = flag.Bool("allow-private", envBoolOrDefault("CERBERUS_ALLOW_PRIVATE", false), "Allow webhook delivery to RFC1918 private addresses")
		metricsAddr   = flag.String("metrics-addr", "", "Optional HTTP listen address for /health and /stats (e.g. 127.0.0.1:9090)")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := dispatcher.OpenAndInitDB(ctx, *dbPath, *schemaPath)
	if err != nil {
		logger.Error("failed to initialize database", "db", *dbPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()

	cfg := dispatcher.Config{
		DBPath:        *dbPath,
		SchemaPath:    *schemaPath,
		PollInterval:  *pollInterval,
		Workers:       *workers,
		HTTPTimeout:   *httpTimeout,
		BatchSize:     *batchSize,
		BaseBackoff:   *baseBackoff,
		AllowLoopback: *allowLoopback,
		AllowPrivate:  *allowPrivate,
		SigningSecret: os.Getenv("CERBERUS_WEBHOOK_SECRET"),
		Logger:        logger,
	}

	disp, err := dispatcher.New(cfg, db)
	if err != nil {
		logger.Error("failed to create dispatcher", "error", err)
		os.Exit(1)
	}

	var metricsSrv *http.Server
	if *metricsAddr != "" {
		srv, err := startMetricsServer(ctx, *metricsAddr, disp, logger)
		if err != nil {
			logger.Error("failed to start metrics server", "addr", *metricsAddr, "error", err)
			os.Exit(1)
		}
		metricsSrv = srv
	}

	if *once {
		processed, err := disp.ProcessBatch(ctx)
		if err != nil {
			logger.Error("single batch execution failed", "error", err)
			shutdownMetrics(metricsSrv)
			os.Exit(1)
		}
		logger.Info("single batch execution completed", "processed", processed)
		shutdownMetrics(metricsSrv)
		return
	}

	if err := disp.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("dispatcher stopped with error", "error", err)
		shutdownMetrics(metricsSrv)
		os.Exit(1)
	}

	shutdownMetrics(metricsSrv)
}

func startMetricsServer(ctx context.Context, addr string, disp *dispatcher.Dispatcher, logger *slog.Logger) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		reqCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		st, err := disp.GetStats(reqCtx)
		if err != nil {
			logger.Error("failed to query stats", "error", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(st)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
	}

	go func() {
		logger.Info("observability server listening", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("observability server error", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownMetrics(srv)
	}()

	return srv, nil
}

func shutdownMetrics(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func envBoolOrDefault(key string, def bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch val {
	case "1", "true", "TRUE", "yes", "YES":
		return true
	case "0", "false", "FALSE", "no", "NO":
		return false
	default:
		return def
	}
}
