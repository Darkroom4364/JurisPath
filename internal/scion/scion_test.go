package scion

import (
	"strings"
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
		if h.IA != testHops[i].IA || h.ISD != testHops[i].ISD || h.AS != testHops[i].AS {
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

// --- FingerprintPath ---

func TestFingerprintPath_UsesRawWhenPresent(t *testing.T) {
	raw := []byte("authenticated-scion-dataplane-bytes")
	fp := FingerprintPath(raw, testHops)
	hopFP := FingerprintHops(testHops)
	if fp == hopFP {
		t.Fatal("FingerprintPath with raw bytes should differ from FingerprintHops")
	}
}

func TestFingerprintPath_FallsBackToHops(t *testing.T) {
	fp := FingerprintPath(nil, testHops)
	hopFP := FingerprintHops(testHops)
	if fp != hopFP {
		t.Fatalf("FingerprintPath without raw should equal FingerprintHops: %s != %s", fp, hopFP)
	}
}

func TestFingerprintPath_EmptyRawFallsBack(t *testing.T) {
	fp := FingerprintPath([]byte{}, testHops)
	hopFP := FingerprintHops(testHops)
	if fp != hopFP {
		t.Fatalf("FingerprintPath with empty raw should equal FingerprintHops: %s != %s", fp, hopFP)
	}
}

func TestFingerprintPath_DeterministicWithRaw(t *testing.T) {
	raw := []byte("same-bytes")
	a := FingerprintPath(raw, testHops)
	b := FingerprintPath(raw, testHops)
	if a != b {
		t.Fatalf("FingerprintPath is not deterministic: %s != %s", a, b)
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
	if p.EvidenceClass != model.EvidenceClassExplicitDemo {
		t.Fatalf("EvidenceClass = %q, want %q", p.EvidenceClass, model.EvidenceClassExplicitDemo)
	}
	if p.ProofStatus != model.ProofStatusUnverified {
		t.Fatalf("ProofStatus = %q, want %q", p.ProofStatus, model.ProofStatusUnverified)
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

func TestBuildSCIONPath_RejectingExtractor(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildSCIONPath(NewRejectingPathExtractor(""), raw)
	if err == nil {
		t.Fatal("expected rejecting extractor to fail")
	}
	if !strings.Contains(err.Error(), "SCION mode") {
		t.Fatalf("error %q does not explain SCION mode rejection", err)
	}
}
