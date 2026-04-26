package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate_Valid(t *testing.T) {
	for _, mode := range []string{"strict", "relaxed"} {
		p := &Policy{ID: "p1", AllowedISDs: []uint16{1}, Mode: mode}
		if err := p.Validate(); err != nil {
			t.Errorf("mode %s: unexpected error: %v", mode, err)
		}
	}
}

func TestValidate_MissingID(t *testing.T) {
	p := &Policy{AllowedISDs: []uint16{1}, Mode: "strict"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestValidate_MissingAllowedISDs(t *testing.T) {
	p := &Policy{ID: "p1", Mode: "strict"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing AllowedISDs")
	}
}

func TestValidate_MissingMode(t *testing.T) {
	p := &Policy{ID: "p1", AllowedISDs: []uint16{1}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing Mode")
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	p := &Policy{ID: "p1", AllowedISDs: []uint16{1}, Mode: "permissive"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

const validYAML = `id: p1
name: Test
allowed_isds: [1, 2]
mode: relaxed
`

func TestLoadFromFile_Valid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(f, []byte(validYAML), 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	p, err := LoadFromFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "p1" || p.Mode != "relaxed" || len(p.AllowedISDs) != 2 {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestLoadFromFile_DefaultMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(f, []byte("id: p1\nallowed_isds: [1]\n"), 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	p, err := LoadFromFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "strict" {
		t.Fatalf("expected default mode 'strict', got %q", p.Mode)
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(f, []byte(":\t:bad"), 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	if _, err := LoadFromFile(f); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFromFile_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := LoadFromFile(missing); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAllFromDir(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []struct{ name, content string }{
		{"a.yaml", "id: a\nallowed_isds: [1]\n"},
		{"b.yaml", "id: b\nallowed_isds: [2]\n"},
		{"c.txt", "ignored"},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.content), 0644); err != nil {
			t.Fatalf("writing %s: %v", f.name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}

	policies, err := LoadAllFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestLoadAllFromDir_ShortFilenames(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []struct{ name, content string }{
		{"a.yaml", "id: a\nallowed_isds: [1]\n"},
		{"bc.yaml", "id: bc\nallowed_isds: [1]\n"},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.content), 0644); err != nil {
			t.Fatalf("writing %s: %v", f.name, err)
		}
	}

	if _, err := LoadAllFromDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAllFromDir_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent")
	if _, err := LoadAllFromDir(missing); err == nil {
		t.Fatal("expected error for missing directory")
	}
}
