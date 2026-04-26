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
	os.WriteFile(f, []byte(validYAML), 0644)

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
	os.WriteFile(f, []byte("id: p1\nallowed_isds: [1]\n"), 0644)

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
	os.WriteFile(f, []byte(":\t:bad"), 0644)

	if _, err := LoadFromFile(f); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFromFile_MissingFile(t *testing.T) {
	if _, err := LoadFromFile("/nonexistent/path/p.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAllFromDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: a\nallowed_isds: [1]\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("id: b\nallowed_isds: [2]\n"), 0644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("ignored"), 0644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

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
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: a\nallowed_isds: [1]\n"), 0644)
	os.WriteFile(filepath.Join(dir, "bc.yaml"), []byte("id: bc\nallowed_isds: [1]\n"), 0644)

	if _, err := LoadAllFromDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAllFromDir_MissingDir(t *testing.T) {
	if _, err := LoadAllFromDir("/nonexistent/dir"); err == nil {
		t.Fatal("expected error for missing directory")
	}
}
