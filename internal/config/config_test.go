package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if err := Validate(cfg); err != nil {
		t.Fatalf("defaults should validate: %v", err)
	}
	if cfg.CollectionInterval != 5*time.Second {
		t.Fatalf("unexpected collection interval: %s", cfg.CollectionInterval)
	}
	if !cfg.BPF.DimensionReason || !cfg.BPF.DimensionLocation || !cfg.BPF.DimensionProtocol {
		t.Fatalf("default dimensions are incomplete: %+v", cfg.BPF)
	}
}

func TestLoadFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	contents := []byte(`
listen_address: "0.0.0.0:9435"
metrics_path: "/custom-metrics"
collection_interval: "250ms"
bpf:
  max_entries: 32
  reason: true
  location: false
  protocol: true
  interface: true
symbolizer:
  kallsyms_path: "/host/proc/kallsyms"
  modules_path: "/host/proc/modules"
  module_refresh_interval: "2m"
logging:
  level: "debug"
  format: "text"
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "0.0.0.0:9435" || cfg.MetricsPath != "/custom-metrics" {
		t.Fatalf("file values not loaded: %+v", cfg)
	}
	if cfg.CollectionInterval != 250*time.Millisecond || cfg.BPF.MaxEntries != 32 {
		t.Fatalf("duration or map values not loaded: %+v", cfg)
	}
	if cfg.BPF.DimensionLocation || !cfg.BPF.DimensionInterface {
		t.Fatalf("dimension values not loaded: %+v", cfg.BPF)
	}
	if cfg.Symbolizer.ModuleRefreshInterval != 2*time.Minute || cfg.Logging.Format != "text" {
		t.Fatalf("nested values not loaded: %+v", cfg)
	}
	if cfg.Symbolizer.KallsymsPath != "/host/proc/kallsyms" || cfg.Symbolizer.ModulesPath != "/host/proc/modules" {
		t.Fatalf("symbolizer paths not loaded: %+v", cfg.Symbolizer)
	}
}

func TestLoadFileKeepsUnsetDimensionDefaults(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "partial.yaml")
	if err := os.WriteFile(path, []byte("bpf:\n  max_entries: 16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BPF.MaxEntries != 16 || !cfg.BPF.DimensionReason || !cfg.BPF.DimensionLocation || !cfg.BPF.DimensionProtocol {
		t.Fatalf("unset defaults were lost: %+v", cfg.BPF)
	}
}

func TestParseCLIOverridesFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte("collection_interval: 1s\nbpf:\n  max_entries: 64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, showVersion, err := Parse([]string{
		"--config.file", path,
		"--collector.interval", "3s",
		"--bpf.max-entries", "128",
	})
	if err != nil {
		t.Fatal(err)
	}
	if showVersion || cfg.CollectionInterval != 3*time.Second || cfg.BPF.MaxEntries != 128 {
		t.Fatalf("CLI override failed: showVersion=%v cfg=%+v", showVersion, cfg)
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	cases := []Config{
		func() Config { cfg := Defaults(); cfg.MetricsPath = "metrics"; return cfg }(),
		func() Config { cfg := Defaults(); cfg.CollectionInterval = 0; return cfg }(),
		func() Config { cfg := Defaults(); cfg.BPF.MaxEntries = 0; return cfg }(),
		func() Config { cfg := Defaults(); cfg.Symbolizer.ModulesPath = ""; return cfg }(),
		func() Config { cfg := Defaults(); cfg.Symbolizer.ModuleRefreshInterval = 0; return cfg }(),
		func() Config { cfg := Defaults(); cfg.Logging.Format = "yaml"; return cfg }(),
	}
	for index, cfg := range cases {
		if err := Validate(cfg); err == nil {
			t.Errorf("case %d unexpectedly validated", index)
		}
	}
}
