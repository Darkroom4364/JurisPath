package scion

import (
	"testing"

	"github.com/jurispath/jurispath/pkg/model"
)

var testHops = []model.ASHop{
	{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
	{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
}

// --- FingerprintHops ---

func TestFingerprintHops_Deterministic(t *testing.T) {
	a := FingerprintHops(testHops)
	b := FingerprintHops(testHops)
	if a != b {
		t.Fatalf("fingerprint is not deterministic: %s != %s", a, b)
	}
}

func TestFingerprintHops_DifferentHopsDiffer(t *testing.T) {
	other := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
	}
	if FingerprintHops(testHops) == FingerprintHops(other) {
		t.Fatal("different hops should produce different fingerprints")
	}
}

func TestFingerprintHops_MockBuildParity(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildSCIONPath(&MockPathExtractor{}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != FingerprintHops(testHops) {
		t.Fatalf("BuildSCIONPath fingerprint %s != FingerprintHops %s", p.Fingerprint, FingerprintHops(testHops))
	}
}

// --- MockPathExtractor ---

func TestMockPathExtractor_ValidHops(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}
	m := &MockPathExtractor{}
	hops, err := m.ExtractHops(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != len(testHops) {
		t.Fatalf("got %d hops, want %d", len(hops), len(testHops))
	}
	for i, h := range hops {
		if h != testHops[i] {
			t.Errorf("hop[%d]: got %+v, want %+v", i, h, testHops[i])
		}
	}
}

func TestMockPathExtractor_InvalidJSON(t *testing.T) {
	m := &MockPathExtractor{}
	_, err := m.ExtractHops([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMockPathExtractor_EmptyArray(t *testing.T) {
	m := &MockPathExtractor{}
	hops, err := m.ExtractHops([]byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 0 {
		t.Fatalf("got %d hops, want 0", len(hops))
	}
}

// --- NewMockPath / round-trip ---

func TestNewMockPath_RoundTrip(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}
	m := &MockPathExtractor{}
	hops, err := m.ExtractHops(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != len(testHops) {
		t.Fatalf("round-trip: got %d hops, want %d", len(hops), len(testHops))
	}
}

// --- BuildSCIONPath ---

func TestBuildSCIONPath_ValidHops(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildSCIONPath(&MockPathExtractor{}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hops) != len(testHops) {
		t.Fatalf("got %d hops, want %d", len(p.Hops), len(testHops))
	}
	if p.Fingerprint != FingerprintHops(testHops) {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestBuildSCIONPath_EmptyHops(t *testing.T) {
	_, err := BuildSCIONPath(&MockPathExtractor{}, []byte("[]"))
	if err == nil {
		t.Fatal("expected error for empty hops")
	}
}

func TestBuildSCIONPath_InvalidJSON(t *testing.T) {
	_, err := BuildSCIONPath(&MockPathExtractor{}, []byte("bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

