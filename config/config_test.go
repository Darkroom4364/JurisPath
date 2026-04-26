package config

import (
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	for _, k := range []string{
		"JURISPATH_LISTEN", "JURISPATH_POLICY_DIR", "JURISPATH_DASHBOARD_DIR",
		"JURISPATH_DATA_DIR", "JURISPATH_LOG_LEVEL", "JURISPATH_ORACLE_KEY",
	} {
		t.Setenv(k, "")
	}
	c := Load()
	if c.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", c.ListenAddr)
	}
	if c.PolicyDir != "policies" {
		t.Errorf("PolicyDir = %q, want policies", c.PolicyDir)
	}
	if c.DashboardDir != "dashboard" {
		t.Errorf("DashboardDir = %q, want dashboard", c.DashboardDir)
	}
	if c.DataDir != "data/" {
		t.Errorf("DataDir = %q, want data/", c.DataDir)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", c.LogLevel)
	}
	if c.OracleKeyPath != "data/oracle.key" {
		t.Errorf("OracleKeyPath = %q, want data/oracle.key", c.OracleKeyPath)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("JURISPATH_LISTEN", ":9090")
	c := Load()
	if c.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want :9090", c.ListenAddr)
	}
}

func TestValidate_ValidDir(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir()}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingDir(t *testing.T) {
	c := &Config{PolicyDir: "/nonexistent/path/xyz"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}
