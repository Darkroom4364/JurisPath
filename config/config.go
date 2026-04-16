package config

import (
	"fmt"
	"os"
)

// Config holds application configuration.
type Config struct {
	ListenAddr   string
	PolicyDir    string
	DashboardDir string
	DataDir      string
	LogLevel     string // "debug", "info", "warn", "error"
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	return &Config{
		ListenAddr:   envOr("JURISPATH_LISTEN", ":8080"),
		PolicyDir:    envOr("JURISPATH_POLICY_DIR", "policies"),
		DashboardDir: envOr("JURISPATH_DASHBOARD_DIR", "dashboard"),
		DataDir:      envOr("JURISPATH_DATA_DIR", "data/"),
		LogLevel:     envOr("JURISPATH_LOG_LEVEL", "info"),
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
