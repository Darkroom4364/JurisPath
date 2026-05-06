package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds application configuration.
type Config struct {
	ListenAddr     string
	PolicyDir      string
	DashboardDir   string
	DataDir        string
	LogLevel       string // "debug", "info", "warn", "error"
	OracleKeyPath  string
	TRCDir         string // optional directory of signed TRCs for receipt ISD proofs
	TLSCert        string // path to TLS certificate file (enables HTTPS)
	TLSKey         string // path to TLS private key file
	AllowInsecure  bool   // explicitly allow plaintext HTTP (JURISPATH_INSECURE=true)
	APIToken       string // bearer token required for /api/* endpoints
	AdminToken     string // privileged token for administrative endpoints
	AllowUnauthAPI bool   // explicitly allow unauthenticated API access for demo/dev
	ValidatorsFile string // path to validators.yaml
	SCIONMode      bool   // true = enable experimental SCION startup/transport wiring
	SCIONDaemon    string // SCION daemon address (e.g. "127.0.0.1:30255")
	ValidatorID    string // this node's validator ID (required in SCION mode)
	ThresholdK     int    // optional threshold receipt signature quorum
	ThresholdN     int    // optional threshold receipt signature group size
}

// Load reads configuration from environment variables with defaults.
func Load() *Config {
	return &Config{
		ListenAddr:     envOr("JURISPATH_LISTEN", ":8080"),
		PolicyDir:      envOr("JURISPATH_POLICY_DIR", "policies"),
		DashboardDir:   envOr("JURISPATH_DASHBOARD_DIR", "dashboard"),
		DataDir:        envOr("JURISPATH_DATA_DIR", "data/"),
		LogLevel:       envOr("JURISPATH_LOG_LEVEL", "info"),
		OracleKeyPath:  envOr("JURISPATH_ORACLE_KEY", "data/oracle.key"),
		TRCDir:         os.Getenv("JURISPATH_TRC_DIR"),
		TLSCert:        os.Getenv("JURISPATH_TLS_CERT"),
		TLSKey:         os.Getenv("JURISPATH_TLS_KEY"),
		AllowInsecure:  os.Getenv("JURISPATH_INSECURE") == "true",
		APIToken:       os.Getenv("JURISPATH_API_TOKEN"),
		AdminToken:     os.Getenv("JURISPATH_ADMIN_TOKEN"),
		AllowUnauthAPI: os.Getenv("JURISPATH_UNAUTHENTICATED_API") == "true",
		ValidatorsFile: envOr("JURISPATH_VALIDATORS", "validators.yaml"),
		SCIONMode:      os.Getenv("JURISPATH_SCION_MODE") == "true",
		SCIONDaemon:    envOr("JURISPATH_SCION_DAEMON", "127.0.0.1:30255"),
		ValidatorID:    os.Getenv("JURISPATH_VALIDATOR_ID"),
		ThresholdK:     envIntOrInvalid("JURISPATH_THRESHOLD_K"),
		ThresholdN:     envIntOrInvalid("JURISPATH_THRESHOLD_N"),
	}
}

// TLSEnabled returns true when both TLS cert and key paths are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}

// Validate checks that required paths exist.
func (c *Config) Validate() error {
	if _, err := os.Stat(c.PolicyDir); err != nil {
		return fmt.Errorf("policy directory %q: %w", c.PolicyDir, err)
	}
	if (c.TLSCert != "") != (c.TLSKey != "") {
		return fmt.Errorf("both JURISPATH_TLS_CERT and JURISPATH_TLS_KEY must be set, or neither")
	}
	if c.TLSEnabled() {
		if _, err := os.Stat(c.TLSCert); err != nil {
			return fmt.Errorf("TLS certificate %q: %w", c.TLSCert, err)
		}
		if _, err := os.Stat(c.TLSKey); err != nil {
			return fmt.Errorf("TLS key %q: %w", c.TLSKey, err)
		}
	}
	if !c.TLSEnabled() && !c.AllowInsecure {
		return fmt.Errorf("TLS not configured; set JURISPATH_TLS_CERT and JURISPATH_TLS_KEY, or set JURISPATH_INSECURE=true to allow plaintext HTTP")
	}
	if c.APIToken == "" && !c.AllowUnauthAPI {
		return fmt.Errorf("API authentication not configured; set JURISPATH_API_TOKEN, or set JURISPATH_UNAUTHENTICATED_API=true for local/demo mode")
	}
	if c.ThresholdK < 0 {
		return fmt.Errorf("JURISPATH_THRESHOLD_K must be a non-negative integer")
	}
	if c.ThresholdN < 0 {
		return fmt.Errorf("JURISPATH_THRESHOLD_N must be a non-negative integer")
	}
	if (c.ThresholdK == 0) != (c.ThresholdN == 0) {
		return fmt.Errorf("both JURISPATH_THRESHOLD_K and JURISPATH_THRESHOLD_N must be set to enable threshold receipt signing")
	}
	if c.ThresholdK > c.ThresholdN {
		return fmt.Errorf("JURISPATH_THRESHOLD_K (%d) cannot exceed JURISPATH_THRESHOLD_N (%d)", c.ThresholdK, c.ThresholdN)
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

func envIntOrInvalid(key string) int {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}
