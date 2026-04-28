package config

import (
	"fmt"
	"os"
)

// Config holds application configuration.
type Config struct {
	ListenAddr    string
	PolicyDir     string
	DashboardDir  string
	DataDir       string
	LogLevel      string // "debug", "info", "warn", "error"
	OracleKeyPath string
	SCIONMode     bool   // true = validators communicate over SCION
	SCIONDaemon   string // SCION daemon address (e.g. "127.0.0.1:30255")
	ValidatorID   string // this node's validator ID (required in SCION mode)
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	return &Config{
		ListenAddr:    envOr("JURISPATH_LISTEN", ":8080"),
		PolicyDir:     envOr("JURISPATH_POLICY_DIR", "policies"),
		DashboardDir:  envOr("JURISPATH_DASHBOARD_DIR", "dashboard"),
		DataDir:       envOr("JURISPATH_DATA_DIR", "data/"),
		LogLevel:      envOr("JURISPATH_LOG_LEVEL", "info"),
		OracleKeyPath: envOr("JURISPATH_ORACLE_KEY", "data/oracle.key"),
		SCIONMode:     os.Getenv("JURISPATH_SCION_MODE") == "true",
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
