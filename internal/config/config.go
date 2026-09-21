package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultMaxEntries uint32 = 8192

// Config is the validated runtime configuration.
type Config struct {
	ListenAddress      string
	MetricsPath        string
	CollectionInterval time.Duration
	BPF                BPFConfig
	Symbolizer         SymbolizerConfig
	Logging            LoggingConfig
}

type BPFConfig struct {
	MaxEntries         uint32 `yaml:"max_entries"`
	DimensionReason    bool   `yaml:"reason"`
	DimensionLocation  bool   `yaml:"location"`
	DimensionProtocol  bool   `yaml:"protocol"`
	DimensionInterface bool   `yaml:"interface"`
}

type SymbolizerConfig struct {
	KallsymsPath          string        `yaml:"kallsyms_path"`
	ModulesPath           string        `yaml:"modules_path"`
	ModuleRefreshInterval time.Duration `yaml:"-"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type fileConfig struct {
	ListenAddress      string          `yaml:"listen_address"`
	MetricsPath        string          `yaml:"metrics_path"`
	CollectionInterval string          `yaml:"collection_interval"`
	BPF                *fileBPFConfig  `yaml:"bpf"`
	Symbolizer         *fileSymbolizer `yaml:"symbolizer"`
	Logging            *LoggingConfig  `yaml:"logging"`
}

type fileBPFConfig struct {
	MaxEntries         *uint32 `yaml:"max_entries"`
	DimensionReason    *bool   `yaml:"reason"`
	DimensionLocation  *bool   `yaml:"location"`
	DimensionProtocol  *bool   `yaml:"protocol"`
	DimensionInterface *bool   `yaml:"interface"`
}

type fileSymbolizer struct {
	KallsymsPath          string `yaml:"kallsyms_path"`
	ModulesPath           string `yaml:"modules_path"`
	ModuleRefreshInterval string `yaml:"module_refresh_interval"`
}

// Defaults returns the configuration described in the implementation plan.
func Defaults() Config {
	return Config{
		ListenAddress:      "127.0.0.1:9435",
		MetricsPath:        "/metrics",
		CollectionInterval: 5 * time.Second,
		BPF: BPFConfig{
			MaxEntries:         defaultMaxEntries,
			DimensionReason:    true,
			DimensionLocation:  true,
			DimensionProtocol:  true,
			DimensionInterface: false,
		},
		Symbolizer: SymbolizerConfig{
			KallsymsPath:          "/proc/kallsyms",
			ModulesPath:           "/proc/modules",
			ModuleRefreshInterval: time.Minute,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadFile merges a YAML configuration file onto Defaults.
func LoadFile(path string) (Config, error) {
	cfg := Defaults()
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config file %q: %w", path, err)
	}
	defer file.Close()

	var raw fileConfig
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode config file %q: %w", path, err)
	}
	if raw.ListenAddress != "" {
		cfg.ListenAddress = raw.ListenAddress
	}
	if raw.MetricsPath != "" {
		cfg.MetricsPath = raw.MetricsPath
	}
	if raw.CollectionInterval != "" {
		interval, err := time.ParseDuration(raw.CollectionInterval)
		if err != nil {
			return Config{}, fmt.Errorf("collection_interval: %w", err)
		}
		cfg.CollectionInterval = interval
	}
	if raw.BPF != nil {
		if raw.BPF.MaxEntries != nil {
			cfg.BPF.MaxEntries = *raw.BPF.MaxEntries
		}
		if raw.BPF.DimensionReason != nil {
			if !*raw.BPF.DimensionReason {
				return Config{}, errors.New("bpf.reason must remain enabled in v1")
			}
			cfg.BPF.DimensionReason = true
		}
		if raw.BPF.DimensionLocation != nil {
			cfg.BPF.DimensionLocation = *raw.BPF.DimensionLocation
		}
		if raw.BPF.DimensionProtocol != nil {
			cfg.BPF.DimensionProtocol = *raw.BPF.DimensionProtocol
		}
		if raw.BPF.DimensionInterface != nil {
			cfg.BPF.DimensionInterface = *raw.BPF.DimensionInterface
		}
	}
	if raw.Symbolizer != nil {
		if raw.Symbolizer.KallsymsPath != "" {
			cfg.Symbolizer.KallsymsPath = raw.Symbolizer.KallsymsPath
		}
		if raw.Symbolizer.ModulesPath != "" {
			cfg.Symbolizer.ModulesPath = raw.Symbolizer.ModulesPath
		}
		if raw.Symbolizer.ModuleRefreshInterval != "" {
			interval, err := time.ParseDuration(raw.Symbolizer.ModuleRefreshInterval)
			if err != nil {
				return Config{}, fmt.Errorf("module_refresh_interval: %w", err)
			}
			cfg.Symbolizer.ModuleRefreshInterval = interval
		}
	}
	if raw.Logging != nil {
		if raw.Logging.Level != "" {
			cfg.Logging.Level = raw.Logging.Level
		}
		if raw.Logging.Format != "" {
			cfg.Logging.Format = raw.Logging.Format
		}
	}

	return cfg, Validate(cfg)
}

// Parse parses CLI flags after optionally loading --config.file. CLI values
// always win over file values because the final FlagSet uses the file values
// as its defaults.
func Parse(args []string) (Config, bool, error) {
	cfg := Defaults()
	configPath := findConfigPath(args)
	if configPath != "" {
		var err error
		cfg, err = LoadFile(configPath)
		if err != nil {
			return Config{}, false, err
		}
	}

	flags := flag.NewFlagSet("packet-drop-exporter", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFile := flags.String("config.file", configPath, "YAML configuration file")
	listenAddress := flags.String("web.listen-address", cfg.ListenAddress, "HTTP listen address")
	metricsPath := flags.String("web.metrics-path", cfg.MetricsPath, "Prometheus metrics path")
	interval := flags.Duration("collector.interval", cfg.CollectionInterval, "BPF collection interval")
	maxEntries := flags.Uint("bpf.max-entries", uint(cfg.BPF.MaxEntries), "maximum number of BPF map entries")
	dimensionLocation := flags.Bool("bpf.dimension-location", cfg.BPF.DimensionLocation, "include kernel location in the key")
	dimensionProtocol := flags.Bool("bpf.dimension-protocol", cfg.BPF.DimensionProtocol, "include L3 protocol in the key")
	dimensionInterface := flags.Bool("bpf.dimension-interface", cfg.BPF.DimensionInterface, "include network namespace and ifindex in the key")
	kallsymsPath := flags.String("symbolizer.kallsyms-path", cfg.Symbolizer.KallsymsPath, "kallsyms file path")
	modulesPath := flags.String("symbolizer.modules-path", cfg.Symbolizer.ModulesPath, "loaded modules file path")
	moduleRefreshInterval := flags.Duration("symbolizer.module-refresh-interval", cfg.Symbolizer.ModuleRefreshInterval, "kernel symbol refresh interval")
	logLevel := flags.String("log.level", cfg.Logging.Level, "log level: debug, info, warn, or error")
	logFormat := flags.String("log.format", cfg.Logging.Format, "log format: text or json")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return Config{}, false, err
	}

	if *configFile != "" && *configFile != configPath {
		return Config{}, false, errors.New("--config.file must be provided before parsing other flags")
	}
	cfg.ListenAddress = *listenAddress
	cfg.MetricsPath = *metricsPath
	cfg.CollectionInterval = *interval
	cfg.BPF.MaxEntries = uint32(*maxEntries)
	cfg.BPF.DimensionLocation = *dimensionLocation
	cfg.BPF.DimensionProtocol = *dimensionProtocol
	cfg.BPF.DimensionInterface = *dimensionInterface
	cfg.BPF.DimensionReason = true
	cfg.Symbolizer.KallsymsPath = *kallsymsPath
	cfg.Symbolizer.ModulesPath = *modulesPath
	cfg.Symbolizer.ModuleRefreshInterval = *moduleRefreshInterval
	cfg.Logging.Level = *logLevel
	cfg.Logging.Format = *logFormat

	return cfg, *showVersion, Validate(cfg)
}

func findConfigPath(args []string) string {
	for index, arg := range args {
		if strings.HasPrefix(arg, "--config.file=") {
			return strings.TrimPrefix(arg, "--config.file=")
		}
		if arg == "--config.file" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

// Validate enforces values which affect map schema or the public HTTP API.
func Validate(cfg Config) error {
	if cfg.ListenAddress == "" {
		return errors.New("listen address must not be empty")
	}
	if !strings.HasPrefix(cfg.MetricsPath, "/") {
		return errors.New("metrics path must start with /")
	}
	if cfg.CollectionInterval <= 0 {
		return errors.New("collection interval must be positive")
	}
	if cfg.BPF.MaxEntries == 0 {
		return errors.New("bpf max entries must be positive")
	}
	if cfg.Symbolizer.KallsymsPath == "" {
		return errors.New("kallsyms path must not be empty")
	}
	if cfg.Symbolizer.ModulesPath == "" {
		return errors.New("modules path must not be empty")
	}
	if cfg.Symbolizer.ModuleRefreshInterval <= 0 {
		return errors.New("module refresh interval must be positive")
	}
	if cfg.Logging.Level != "debug" && cfg.Logging.Level != "info" && cfg.Logging.Level != "warn" && cfg.Logging.Level != "error" {
		return fmt.Errorf("unsupported log level %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" && cfg.Logging.Format != "json" {
		return fmt.Errorf("unsupported log format %q", cfg.Logging.Format)
	}
	return nil
}
