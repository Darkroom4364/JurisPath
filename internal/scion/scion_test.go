package scion

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/jurispath/jurispath/pkg/model"
)

var testHops = []model.ASHop{
	{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
	{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
}

// --- Fingerprint ---

func TestFingerprint_KnownValue(t *testing.T) {
	raw := []byte("hello")
	h := sha256.Sum256(raw)
	want := fmt.Sprintf("%x", h)
	if got := Fingerprint(raw); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	raw := []byte("test-path-bytes")
	a := Fingerprint(raw)
	b := Fingerprint(raw)
	if a != b {
		t.Fatalf("fingerprint is not deterministic: %s != %s", a, b)
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
	if p.Fingerprint != Fingerprint(raw) {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestBuildSCIONPath_InvalidJSON(t *testing.T) {
	_, err := BuildSCIONPath(&MockPathExtractor{}, []byte("bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- SnetPathExtractor.ExtractHops ---

func TestSnetPathExtractor_DelegatesToMock(t *testing.T) {
	raw, err := NewMockPath(testHops)
	if err != nil {
		t.Fatal(err)
	}
	snet := &SnetPathExtractor{}
	hops, err := snet.ExtractHops(raw)
	if err != nil {
		t.Fatal(err)
	}
	mock := &MockPathExtractor{}
	wantHops, err := mock.ExtractHops(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != len(wantHops) {
		t.Fatalf("got %d hops, want %d", len(hops), len(wantHops))
	}
	for i := range hops {
		if hops[i] != wantHops[i] {
			t.Errorf("hop[%d]: got %+v, want %+v", i, hops[i], wantHops[i])
		}
	}
}
