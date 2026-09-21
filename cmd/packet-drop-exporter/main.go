package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kimitoboku/packet_drop_exporter/internal/bpf"
	"github.com/kimitoboku/packet_drop_exporter/internal/collector"
	"github.com/kimitoboku/packet_drop_exporter/internal/config"
	"github.com/kimitoboku/packet_drop_exporter/internal/reason"
	"github.com/kimitoboku/packet_drop_exporter/internal/symbol"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "packet-drop-exporter: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, showVersion, err := config.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	if showVersion {
		fmt.Println(version)
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("packet-drop-exporter requires Linux; use the Docker Linux test environment on macOS")
	}

	logger := newLogger(cfg)
	logger.Info("starting packet drop exporter", "version", version, "listen_address", cfg.ListenAddress, "max_entries", cfg.BPF.MaxEntries)

	reasons, err := reason.LoadKernel()
	if err != nil {
		return err
	}

	symbols, err := symbol.Load(cfg.Symbolizer.KallsymsPath)
	if err != nil {
		logger.Warn("kernel symbols unavailable; locations will be grouped as unknown", "error", err)
		symbols = symbol.New(nil)
	} else if !symbols.Available() {
		logger.Warn("kernel symbols contain no addressable entries; locations will be grouped as unknown")
	}

	source, err := bpf.Open(bpf.LoaderConfig{
		MaxEntries:         cfg.BPF.MaxEntries,
		DimensionLocation:  cfg.BPF.DimensionLocation,
		DimensionProtocol:  cfg.BPF.DimensionProtocol,
		DimensionInterface: cfg.BPF.DimensionInterface,
	})
	if err != nil {
		return err
	}
	defer source.Close()

	store := collector.NewStore()
	runtimeState := &collector.Runtime{}
	resolutionStats := collector.NewResolutionStats()
	runtimeState.SetAttached(true)
	if err := collectOnce(source, store, runtimeState, reasons, symbols, resolutionStats, cfg.BPF.DimensionInterface); err != nil {
		return fmt.Errorf("initial BPF collection: %w", err)
	}
	initialSnapshot := store.Load()
	logger.Info("BPF collector ready",
		"map_max_entries", initialSnapshot.Self.MapMaxEntries,
		"map_estimated_bytes", initialSnapshot.Self.MapEstimatedBytes,
		"symbolizer_available", initialSnapshot.Self.SymbolizerAvailable,
	)
	runtimeState.SetReady(true)

	registry := prometheus.NewRegistry()
	metricsCollector := collector.NewMetricsCollectorWithDimensions(store, runtimeState, version, collector.MetricDimensions{
		Location:  cfg.BPF.DimensionLocation,
		Protocol:  cfg.BPF.DimensionProtocol,
		Interface: cfg.BPF.DimensionInterface,
	})
	registry.MustRegister(metricsCollector)
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())

	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/-/healthy", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/-/ready", func(writer http.ResponseWriter, _ *http.Request) {
		if !runtimeState.Ready() {
			http.Error(writer, "not ready\n", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go runCollectionLoop(ctx, source, store, runtimeState, reasons, symbols, resolutionStats, cfg.CollectionInterval, cfg.BPF.DimensionInterface, logger)
	go runSymbolRefreshLoop(ctx, symbols, runtimeState, cfg.Symbolizer.KallsymsPath, cfg.Symbolizer.ModulesPath, cfg.Symbolizer.ModuleRefreshInterval, logger)

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("HTTP server listening", "address", cfg.ListenAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
		close(serverErrors)
	}()

	select {
	case err := <-serverErrors:
		if err != nil {
			return fmt.Errorf("HTTP server: %w", err)
		}
	case <-ctx.Done():
		logger.Info("shutdown requested")
	}

	runtimeState.SetReady(false)
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	return nil
}

func runSymbolRefreshLoop(ctx context.Context, symbols *symbol.Resolver, runtimeState *collector.Runtime, kallsymsPath, modulesPath string, interval time.Duration, logger *slog.Logger) {
	refresher := symbol.NewRefresher(symbols, kallsymsPath, modulesPath)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshed, err := refresher.RefreshIfChanged()
			if err != nil {
				runtimeState.SymbolRefreshFailure()
				logger.Warn("kernel symbol refresh failed; retaining previous table", "error", err)
				continue
			}
			if refreshed {
				logger.Info("kernel symbol table refreshed", "available", symbols.Available())
			}
		}
	}
}

func collectOnce(source interface {
	Collect() (bpf.RawSnapshot, error)
}, store *collector.Store, runtimeState *collector.Runtime, reasons *reason.Resolver, symbols *symbol.Resolver, resolutionStats *collector.ResolutionStats, interfaceDimension bool) error {
	started := time.Now()
	raw, err := source.Collect()
	if err != nil {
		runtimeState.CollectionFailure()
		return err
	}
	snapshot := collector.BuildSnapshotWithStats(raw, time.Now(), reasons, symbols, interfaceDimension, resolutionStats)
	snapshot.Self.CollectionDurationSeconds = time.Since(started).Seconds()
	store.Store(snapshot)
	return nil
}

func runCollectionLoop(ctx context.Context, source interface {
	Collect() (bpf.RawSnapshot, error)
}, store *collector.Store, runtimeState *collector.Runtime, reasons *reason.Resolver, symbols *symbol.Resolver, resolutionStats *collector.ResolutionStats, interval time.Duration, interfaceDimension bool, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := collectOnce(source, store, runtimeState, reasons, symbols, resolutionStats, interfaceDimension); err != nil {
				logger.Error("BPF collection failed; retaining previous snapshot", "error", err)
			}
		}
	}
}

func newLogger(cfg config.Config) *slog.Logger {
	level := new(slog.LevelVar)
	switch cfg.Logging.Level {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	options := &slog.HandlerOptions{Level: level}
	if cfg.Logging.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, options))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, options))
}
