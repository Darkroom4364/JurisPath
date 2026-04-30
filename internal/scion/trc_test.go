package scion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewTRCProofProvider_EmptyDir(t *testing.T) {
	_, err := NewTRCProofProvider(t.TempDir())
	if err == nil {
		t.Fatal("expected error for empty TRC directory")
	}
	if !strings.Contains(err.Error(), "contains no .trc files") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTRCProofProvider_InvalidTRC(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ISD1-B1-S1.trc"), []byte("not a signed TRC"), 0644); err != nil {
		t.Fatalf("writing invalid TRC: %v", err)
	}

	_, err := NewTRCProofProvider(dir)
	if err == nil {
		t.Fatal("expected error for invalid TRC")
	}
	if !strings.Contains(err.Error(), "decoding TRC") {
		t.Fatalf("unexpected error: %v", err)
	}
}
