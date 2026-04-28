package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds application configuration.
type Config struct {
	ListenAddr    string
	PolicyDir     string
	DashboardDir  string
	DataDir       string
	LogLevel      string // "debug", "info", "warn", "error"
	OracleKeyPath string
	ValidatorsFile string // path to validators.yaml
	SCIONMode      bool   // true = validators communicate over SCION
	SCIONDaemon    string // SCION daemon address (e.g. "127.0.0.1:30255")
	ValidatorID    string // this node's validator ID (required in SCION mode)
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	return &Config{
		ListenAddr:    envOr("JURISPATH_LISTEN", ":8080"),
		PolicyDir:     envOr("JURISPATH_POLICY_DIR", "policies"),
		DashboardDir:  envOr("JURISPATH_DASHBOARD_DIR", "dashboard"),
		DataDir:       envOr("JURISPATH_DATA_DIR", "data/"),
		LogLevel:      envOr("JURISPATH_LOG_LEVEL", "info"),
		OracleKeyPath:  envOr("JURISPATH_ORACLE_KEY", "data/oracle.key"),
		ValidatorsFile: envOr("JURISPATH_VALIDATORS", "validators.yaml"),
		SCIONMode:      os.Getenv("JURISPATH_SCION_MODE") == "true",
		SCIONDaemon:   envOr("JURISPATH_SCION_DAEMON", "127.0.0.1:30255"),
		ValidatorID:   os.Getenv("JURISPATH_VALIDATOR_ID"),
	}
}

// Validate checks that required paths exist.
func (c *Config) Validate() error {
	if _, err := os.Stat(c.PolicyDir); err != nil {
		return fmt.Errorf("policy directory %q: %w", c.PolicyDir, err)
	}
	return nil
}

// ValidatorConfig describes a validator as loaded from validators.yaml.
type ValidatorConfig struct {
	ID      string           `yaml:"id"`
	Address string           `yaml:"address"`
	Balance map[string]int64 `yaml:"balance"`
}

// LoadValidators reads validator definitions from a YAML file.
func LoadValidators(path string) ([]ValidatorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading validators file %q: %w", path, err)
	}

	var validators []ValidatorConfig
	if err := yaml.Unmarshal(data, &validators); err != nil {
		return nil, fmt.Errorf("parsing validators file %q: %w", path, err)
	}

	if len(validators) == 0 {
		return nil, fmt.Errorf("validators file %q contains no validators", path)
	}

	seen := make(map[string]bool, len(validators))
	for i, v := range validators {
		if v.ID == "" {
			return nil, fmt.Errorf("validator %d in %q has no id", i, path)
		}
		if v.Address == "" {
			return nil, fmt.Errorf("validator %q in %q has no address", v.ID, path)
		}
		if seen[v.ID] {
			return nil, fmt.Errorf("duplicate validator id %q in %q", v.ID, path)
		}
		seen[v.ID] = true
	}

	return validators, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
