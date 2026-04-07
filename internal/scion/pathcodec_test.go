package scion

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

// buildTestBinaryPath encodes ISD-AS values into the binary metadata format.
func buildTestBinaryPath(ifaces ...addr.IA) []byte {
	buf := make([]byte, 1+2+len(ifaces)*8)
	buf[0] = pathMetaVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ifaces)))
	for i, ia := range ifaces {
		binary.BigEndian.PutUint64(buf[3+i*8:3+i*8+8], uint64(ia))
	}
	return buf
}

func TestDecodeSnetPathMeta_Deduplication(t *testing.T) {
	ia1 := addr.MustIAFrom(1, 0xff0000000110) // 1-ff00:0:110
	ia2 := addr.MustIAFrom(2, 0xff0000000210) // 2-ff00:0:210

	// 3 interfaces: ia1, ia2, ia1 (duplicate should be deduplicated)
	buf := buildTestBinaryPath(ia1, ia2, ia1)

	hops, err := decodeSnetPathMeta(buf)
	if err != nil {
		t.Fatalf("decodeSnetPathMeta: %v", err)
	}

	if len(hops) != 2 {
		t.Fatalf("expected 2 unique hops, got %d", len(hops))
	}

	if hops[0].ISD != 1 {
		t.Errorf("hop[0].ISD = %d, want 1", hops[0].ISD)
	}
	if hops[1].ISD != 2 {
		t.Errorf("hop[1].ISD = %d, want 2", hops[1].ISD)
	}
	if hops[0].IA != ia1.String() {
		t.Errorf("hop[0].IA = %q, want %q", hops[0].IA, ia1.String())
	}
	if hops[1].IA != ia2.String() {
		t.Errorf("hop[1].IA = %q, want %q", hops[1].IA, ia2.String())
	}
	if hops[0].AS != ia1.AS().String() {
		t.Errorf("hop[0].AS = %q, want %q", hops[0].AS, ia1.AS().String())
	}
}

func TestDecodeSnetPathMeta_SingleHop(t *testing.T) {
	ia := addr.MustIAFrom(1, 0xff0000000110)
	buf := buildTestBinaryPath(ia)

	hops, err := decodeSnetPathMeta(buf)
	if err != nil {
		t.Fatalf("decodeSnetPathMeta: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].ISD != 1 {
		t.Errorf("hop.ISD = %d, want 1", hops[0].ISD)
	}
}

func TestDecodeSnetPathMeta_AllDuplicates(t *testing.T) {
	ia := addr.MustIAFrom(1, 0xff0000000110)
	buf := buildTestBinaryPath(ia, ia, ia)

	hops, err := decodeSnetPathMeta(buf)
	if err != nil {
		t.Fatalf("decodeSnetPathMeta: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop after dedup, got %d", len(hops))
	}
}

func TestDecodeSnetPathMeta_ZeroInterfaces(t *testing.T) {
	// Valid header claiming 0 interfaces -> should error "no hops found"
	buf := []byte{pathMetaVersion, 0x00, 0x00}
	_, err := decodeSnetPathMeta(buf)
	if err == nil {
		t.Fatal("expected error for zero interfaces")
	}
	if !strings.Contains(err.Error(), "no hops") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeSnetPathMeta_EmptyInput(t *testing.T) {
	_, err := decodeSnetPathMeta([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestDecodeSnetPathMeta_TooShort(t *testing.T) {
	_, err := decodeSnetPathMeta([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

func TestDecodeSnetPathMeta_BadVersion(t *testing.T) {
	buf := []byte{0xFF, 0x00, 0x00}
	_, err := decodeSnetPathMeta(buf)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' in error, got: %v", err)
	}
}

func TestDecodeSnetPathMeta_Truncated(t *testing.T) {
	// Claims 2 interfaces but only has bytes for 1
	buf := make([]byte, 1+2+8)
	buf[0] = pathMetaVersion
	binary.BigEndian.PutUint16(buf[1:3], 2) // claims 2
	_, err := decodeSnetPathMeta(buf)
	if err == nil {
		t.Fatal("expected error for truncated interface data")
	}
}

func TestSnetPathExtractor_ExtractHops_BinaryFormat(t *testing.T) {
	ext := &SnetPathExtractor{}

	ia1 := addr.MustIAFrom(1, 0xff0000000110)
	ia2 := addr.MustIAFrom(2, 0xff0000000210)
	buf := buildTestBinaryPath(ia1, ia2)

	hops, err := ext.ExtractHops(buf)
	if err != nil {
		t.Fatalf("ExtractHops: %v", err)
	}
	if len(hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(hops))
	}
}

func TestSnetPathExtractor_ExtractHops_JSONFallback(t *testing.T) {
	ext := &SnetPathExtractor{}

	jsonPath := []byte(`[{"ia":"1-ff00:0:110","isd":1,"as":"ff00:0:110"}]`)
	hops, err := ext.ExtractHops(jsonPath)
	if err != nil {
		t.Fatalf("ExtractHops JSON fallback: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].ISD != 1 {
		t.Errorf("hop.ISD = %d, want 1", hops[0].ISD)
	}
}

func TestSnetPathExtractor_ExtractHops_InvalidInput(t *testing.T) {
	ext := &SnetPathExtractor{}

	// Not binary (doesn't start with 0x01), not valid JSON
	_, err := ext.ExtractHops([]byte("not json or binary"))
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestSnetPathExtractor_ExtractHops_UnknownVersion(t *testing.T) {
	ext := &SnetPathExtractor{}

	// Starts with version 0x02 — should not be treated as valid binary,
	// falls through to JSON which will also fail
	buf := []byte{0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	_, err := ext.ExtractHops(buf)
	if err == nil {
		t.Fatal("expected error for unknown binary version")
	}
}

func TestBuildSCIONPath_WithBinaryInput(t *testing.T) {
	ext := &SnetPathExtractor{}

	ia1 := addr.MustIAFrom(1, 0xff0000000110)
	ia2 := addr.MustIAFrom(3, 0xff0000000310)
	buf := buildTestBinaryPath(ia1, ia2)

	path, err := BuildSCIONPath(ext, buf)
	if err != nil {
		t.Fatalf("BuildSCIONPath: %v", err)
	}
	if len(path.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(path.Hops))
	}
	if path.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}
