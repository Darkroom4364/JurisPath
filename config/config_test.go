package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	for _, k := range []string{
		"JURISPATH_LISTEN", "JURISPATH_POLICY_DIR", "JURISPATH_DASHBOARD_DIR",
		"JURISPATH_DATA_DIR", "JURISPATH_LOG_LEVEL", "JURISPATH_ORACLE_KEY",
		"JURISPATH_TRC_DIR", "JURISPATH_API_TOKEN", "JURISPATH_ADMIN_TOKEN",
		"JURISPATH_UNAUTHENTICATED_API", "JURISPATH_THRESHOLD_K",
		"JURISPATH_THRESHOLD_N",
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
	if c.TRCDir != "" {
		t.Errorf("TRCDir = %q, want empty", c.TRCDir)
	}
	if c.APIToken != "" {
		t.Errorf("APIToken = %q, want empty", c.APIToken)
	}
	if c.AdminToken != "" {
		t.Errorf("AdminToken = %q, want empty", c.AdminToken)
	}
	if c.AllowUnauthAPI {
		t.Error("AllowUnauthAPI should default to false")
	}
	if c.ThresholdK != 0 {
		t.Errorf("ThresholdK = %d, want 0", c.ThresholdK)
	}
	if c.ThresholdN != 0 {
		t.Errorf("ThresholdN = %d, want 0", c.ThresholdN)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("JURISPATH_LISTEN", ":9090")
	t.Setenv("JURISPATH_TRC_DIR", "/tmp/trcs")
	t.Setenv("JURISPATH_API_TOKEN", "secret-token")
	t.Setenv("JURISPATH_ADMIN_TOKEN", "admin-token")
	t.Setenv("JURISPATH_UNAUTHENTICATED_API", "true")
	t.Setenv("JURISPATH_THRESHOLD_K", "2")
	t.Setenv("JURISPATH_THRESHOLD_N", "3")
	c := Load()
	if c.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want :9090", c.ListenAddr)
	}
	if c.APIToken != "secret-token" {
		t.Errorf("APIToken = %q, want secret-token", c.APIToken)
	}
	if c.TRCDir != "/tmp/trcs" {
		t.Errorf("TRCDir = %q, want /tmp/trcs", c.TRCDir)
	}
	if c.AdminToken != "admin-token" {
		t.Errorf("AdminToken = %q, want admin-token", c.AdminToken)
	}
	if !c.AllowUnauthAPI {
		t.Error("AllowUnauthAPI should be true")
	}
	if c.ThresholdK != 2 {
		t.Errorf("ThresholdK = %d, want 2", c.ThresholdK)
	}
	if c.ThresholdN != 3 {
		t.Errorf("ThresholdN = %d, want 3", c.ThresholdN)
	}
}

func TestValidate_ValidDir(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), AllowInsecure: true, APIToken: "secret-token"}
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

func TestValidate_TLSPartial(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), TLSCert: "cert.pem"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when TLSCert set without TLSKey")
	}
	c = &Config{PolicyDir: t.TempDir(), TLSKey: "key.pem"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when TLSKey set without TLSCert")
	}
}

func TestValidate_NoTLSNoInsecure(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), APIToken: "secret-token"}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error when neither TLS nor AllowInsecure is set")
	}
}

func TestValidate_NoAPITokenNoUnauthenticatedAPI(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), AllowInsecure: true}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error when neither APIToken nor AllowUnauthAPI is set")
	}
}

func TestValidate_ExplicitUnauthenticatedAPI(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), AllowInsecure: true, AllowUnauthAPI: true}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_ThresholdConfig(t *testing.T) {
	tests := []struct {
		name string
		k    int
		n    int
		ok   bool
	}{
		{name: "disabled", k: 0, n: 0, ok: true},
		{name: "valid", k: 2, n: 3, ok: true},
		{name: "partial k", k: 2, n: 0},
		{name: "partial n", k: 0, n: 3},
		{name: "k exceeds n", k: 4, n: 3},
		{name: "invalid k", k: -1, n: 3},
		{name: "invalid n", k: 2, n: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				PolicyDir:     t.TempDir(),
				AllowInsecure: true,
				APIToken:      "secret-token",
				ThresholdK:    tc.k,
				ThresholdN:    tc.n,
			}
			err := c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected threshold validation error")
			}
		})
	}
}

func TestValidate_TLSFilesExist(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0644); err != nil {
		t.Fatalf("writing cert fixture: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0644); err != nil {
		t.Fatalf("writing key fixture: %v", err)
	}
	c := &Config{PolicyDir: dir, TLSCert: certPath, TLSKey: keyPath, APIToken: "secret-token"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_TLSFilesMissing(t *testing.T) {
	c := &Config{PolicyDir: t.TempDir(), TLSCert: "/nonexistent/cert.pem", TLSKey: "/nonexistent/key.pem", APIToken: "secret-token"}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error for missing TLS cert file")
	}
}

func TestTLSEnabled(t *testing.T) {
	c := &Config{}
	if c.TLSEnabled() {
		t.Error("TLSEnabled should be false when both are empty")
	}
	c.TLSCert = "cert.pem"
	c.TLSKey = "key.pem"
	if !c.TLSEnabled() {
		t.Error("TLSEnabled should be true when both are set")
	}
}

func TestLoadValidators_Valid(t *testing.T) {
	content := `
- id: CH
  address: "1-ff00:0:111,[127.0.0.1]:30100"
  balance:
    CHF: 10000
    EUR: 5000
- id: EU
  address: "2-ff00:0:211,[127.0.0.1]:30200"
  balance:
    CHF: 5000
`
	path := filepath.Join(t.TempDir(), "validators.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	validators, err := LoadValidators(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(validators) != 2 {
		t.Fatalf("expected 2 validators, got %d", len(validators))
	}
	if validators[0].ID != "CH" {
		t.Errorf("expected CH, got %s", validators[0].ID)
	}
	if validators[0].Balance["CHF"] != 10000 {
		t.Errorf("expected 10000 CHF, got %d", validators[0].Balance["CHF"])
	}
	if validators[1].Address != "2-ff00:0:211,[127.0.0.1]:30200" {
		t.Errorf("unexpected address: %s", validators[1].Address)
	}
}

func TestLoadValidators_MissingFile(t *testing.T) {
	_, err := LoadValidators("/nonexistent/validators.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadValidators_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validators.yaml")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := LoadValidators(path)
	if err == nil {
		t.Fatal("expected error for empty validators")
	}
}

func TestLoadValidators_MissingID(t *testing.T) {
	content := `
- address: "1-ff00:0:111,[127.0.0.1]:30100"
  balance:
    CHF: 10000
`
	path := filepath.Join(t.TempDir(), "validators.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := LoadValidators(path)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestLoadValidators_MissingAddress(t *testing.T) {
	content := `
- id: CH
  balance:
    CHF: 10000
`
	path := filepath.Join(t.TempDir(), "validators.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := LoadValidators(path)
	if err == nil {
		t.Fatal("expected error for missing address")
	}
}

func TestLoadValidators_DuplicateID(t *testing.T) {
	content := `
- id: CH
  address: "1-ff00:0:111,[127.0.0.1]:30100"
  balance:
    CHF: 10000
- id: CH
  address: "1-ff00:0:112,[127.0.0.1]:30101"
  balance:
    CHF: 5000
`
	path := filepath.Join(t.TempDir(), "validators.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := LoadValidators(path)
	if err == nil {
		t.Fatal("expected error for duplicate validator id")
	}
}
