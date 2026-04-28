package scion

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/scionproto/scion/pkg/daemon"
	scionpath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"

	"github.com/jurispath/jurispath/pkg/model"
)

// PathExtractor extracts AS hop information from raw SCION path bytes.
type PathExtractor interface {
	ExtractHops(rawPath []byte) ([]model.ASHop, error)
}

// FingerprintHops computes a deterministic SHA-256 fingerprint from the hop
// sequence. This is the fallback fingerprint used in mock mode where raw
// SCION path bytes are not available.
func FingerprintHops(hops []model.ASHop) string {
	var buf []byte
	for _, h := range hops {
		buf = append(buf, h.IA...)
		buf = append(buf, '/')
	}
	hash := sha256.Sum256(buf)
	return fmt.Sprintf("%x", hash)
}

// FingerprintPath computes a fingerprint from the actual SCION dataplane path
// bytes when available, falling back to FingerprintHops for mock mode.
// This ensures receipts bind to the authenticated path data, not a
// text reconstruction.
func FingerprintPath(raw []byte, hops []model.ASHop) string {
	if len(raw) > 0 {
		hash := sha256.Sum256(raw)
		return fmt.Sprintf("%x", hash)
	}
	return FingerprintHops(hops)
}

// BuildSCIONPath constructs a SCIONPath from raw bytes using the given extractor.
func BuildSCIONPath(extractor PathExtractor, raw []byte) (*model.SCIONPath, error) {
	slog.Debug("building SCION path from raw bytes", "raw_len", len(raw))
	hops, err := extractor.ExtractHops(raw)
	if err != nil {
		slog.Error("hop extraction failed", "raw_len", len(raw), "error", err)
		return nil, fmt.Errorf("extracting hops: %w", err)
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("no hops found in raw path")
	}
	fp := FingerprintHops(hops)
	slog.Debug("SCION path built", "hops", len(hops), "fingerprint", fp)
	return &model.SCIONPath{
		Raw:         raw,
		Hops:        hops,
		Fingerprint: fp,
	}, nil
}

// SnetPathExtractor extracts hop information from real SCION snet.Path objects.
// It wraps a daemon.Connector for additional AS lookups if needed.
type SnetPathExtractor struct {
	Conn daemon.Connector
}

// NewSnetPathExtractor creates a new SnetPathExtractor with the given daemon connector.
func NewSnetPathExtractor(conn daemon.Connector) *SnetPathExtractor {
	return &SnetPathExtractor{Conn: conn}
}

// ExtractHopsFromSnetPath reads path.Metadata().Interfaces and extracts
// unique ISD-AS hops in the order they appear along the path.
func (e *SnetPathExtractor) ExtractHopsFromSnetPath(p snet.Path) ([]model.ASHop, error) {
	meta := p.Metadata()
	if meta == nil {
		slog.Error("snet path has nil metadata")
		return nil, fmt.Errorf("path metadata is nil")
	}

	slog.Debug("extracting hops from snet path", "interfaces", len(meta.Interfaces))

	seen := make(map[string]bool)
	var hops []model.ASHop

	for _, iface := range meta.Interfaces {
		ia := iface.IA
		iaStr := ia.String()
		if seen[iaStr] {
			continue
		}
		seen[iaStr] = true

		hops = append(hops, model.ASHop{
			IA:  iaStr,
			ISD: uint16(ia.ISD()),
			AS:  ia.AS().String(),
		})
	}

	if len(hops) == 0 {
		slog.Warn("no hops found in path metadata")
		return nil, fmt.Errorf("no hops found in path metadata")
	}

	slog.Debug("snet path hops extracted", "count", len(hops))
	return hops, nil
}

// BuildSCIONPathFromSnet constructs a model.SCIONPath from a real snet.Path,
// including the raw dataplane bytes and hop field MACs for receipt signing.
func BuildSCIONPathFromSnet(extractor *SnetPathExtractor, p snet.Path) (*model.SCIONPath, error) {
	hops, err := extractor.ExtractHopsFromSnetPath(p)
	if err != nil {
		return nil, fmt.Errorf("extracting hops from snet path: %w", err)
	}

	// Serialize the actual SCION dataplane path bytes so receipts can
	// bind to the authenticated path, not a text reconstruction.
	var rawPath []byte
	if dp := p.Dataplane(); dp != nil {
		rawPath, err = serializeDataplanePath(dp)
		if err != nil {
			slog.Warn("failed to serialize dataplane path", "error", err)
			// Non-fatal: fall back to hop-string fingerprint.
		}
	}

	// Extract hop field MACs from the decoded path.
	extractHopMACs(rawPath, hops)

	return &model.SCIONPath{
		Raw:         rawPath,
		Hops:        hops,
		Fingerprint: FingerprintPath(rawPath, hops),
	}, nil
}

// serializeDataplanePath serializes a SCION DataplanePath to raw bytes.
func serializeDataplanePath(dp snet.DataplanePath) ([]byte, error) {
	// RawPath already carries serialized bytes.
	if rp, ok := dp.(snet.RawPath); ok {
		out := make([]byte, len(rp.Raw))
		copy(out, rp.Raw)
		return out, nil
	}

	// For other path types, attempt to serialize via the slayers interface.
	type serializer interface {
		Len() int
		SerializeTo([]byte) error
	}
	if s, ok := dp.(serializer); ok {
		buf := make([]byte, s.Len())
		if err := s.SerializeTo(buf); err != nil {
			return nil, fmt.Errorf("serializing path: %w", err)
		}
		return buf, nil
	}

	return nil, fmt.Errorf("unsupported dataplane path type %T", dp)
}

// extractHopMACs decodes raw SCION path bytes and attaches hop field MACs
// to the corresponding ASHop entries (matched by position).
func extractHopMACs(raw []byte, hops []model.ASHop) {
	if len(raw) == 0 {
		return
	}
	var decoded scionpath.Decoded
	if err := decoded.DecodeFromBytes(raw); err != nil {
		slog.Debug("failed to decode path for hop MACs", "error", err)
		return
	}
	// Map hop fields to ASHop entries. In a SCION path each interface pair
	// corresponds to one hop field; we distribute MACs across the unique
	// AS hops in order.
	for i := range hops {
		if i < len(decoded.HopFields) {
			mac := decoded.HopFields[i].Mac
			hops[i].HopMAC = mac[:]
		}
	}
}
