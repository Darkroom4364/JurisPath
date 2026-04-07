package scion

import (
	"encoding/binary"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

func TestDecodeSnetPathMeta_RoundTrip(t *testing.T) {
	// Build a valid binary-encoded path with 3 interfaces (2 unique ISD-ASes).
	ia1 := addr.MustIAFrom(1, 0xff0000000110) // 1-ff00:0:110
	ia2 := addr.MustIAFrom(2, 0xff0000000210) // 2-ff00:0:210

	// 3 interfaces: ia1, ia2, ia1 (duplicate should be deduplicated)
	ifaces := []addr.IA{ia1, ia2, ia1}
	buf := make([]byte, 1+2+len(ifaces)*8)
	buf[0] = pathMetaVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ifaces)))
	for i, ia := range ifaces {
		binary.BigEndian.PutUint64(buf[3+i*8:3+i*8+8], uint64(ia))
	}

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

	ifaces := []addr.IA{ia1, ia2}
	buf := make([]byte, 1+2+len(ifaces)*8)
	buf[0] = pathMetaVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ifaces)))
	for i, ia := range ifaces {
		binary.BigEndian.PutUint64(buf[3+i*8:3+i*8+8], uint64(ia))
	}

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
