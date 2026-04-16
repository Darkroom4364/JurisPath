package scion

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"

	"github.com/jurispath/jurispath/pkg/model"
)

// PathExtractor extracts AS hop information from SCION paths.
// In production this wraps snet.Path; for testing we use MockPathExtractor.
type PathExtractor interface {
	ExtractHops(rawPath []byte) ([]model.ASHop, error)
}

// Fingerprint computes a SHA-256 fingerprint of a serialized path.
func Fingerprint(raw []byte) string {
	h := sha256.Sum256(raw)
	return fmt.Sprintf("%x", h)
}

// BuildSCIONPath constructs a SCIONPath from raw bytes using the given extractor.
func BuildSCIONPath(extractor PathExtractor, raw []byte) (*model.SCIONPath, error) {
	slog.Debug("building SCION path from raw bytes", "raw_len", len(raw))
	hops, err := extractor.ExtractHops(raw)
	if err != nil {
		slog.Error("hop extraction failed", "raw_len", len(raw), "error", err)
		return nil, fmt.Errorf("extracting hops: %w", err)
	}
	fp := Fingerprint(raw)
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

// ExtractHops implements PathExtractor for raw bytes. This is a fallback that
// treats raw bytes as a JSON-encoded mock path for backward compatibility.
// For real SCION paths, use ExtractHopsFromSnetPath instead.
func (e *SnetPathExtractor) ExtractHops(rawPath []byte) ([]model.ASHop, error) {
	// Delegate to mock-style JSON decoding as a fallback for raw bytes.
	mock := &MockPathExtractor{}
	return mock.ExtractHops(rawPath)
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
			AS:  fmt.Sprintf("%s", ia.AS()),
		})
	}

	if len(hops) == 0 {
		slog.Warn("no hops found in path metadata")
		return nil, fmt.Errorf("no hops found in path metadata")
	}

	slog.Debug("snet path hops extracted", "count", len(hops))
	return hops, nil
}

// BuildSCIONPathFromSnet constructs a model.SCIONPath from a real snet.Path.
func BuildSCIONPathFromSnet(extractor *SnetPathExtractor, p snet.Path) (*model.SCIONPath, error) {
	hops, err := extractor.ExtractHopsFromSnetPath(p)
	if err != nil {
		return nil, fmt.Errorf("extracting hops from snet path: %w", err)
	}

	// Build a deterministic raw representation for fingerprinting.
	// We serialize the hop sequence since the DataplanePath interface
	// does not expose raw bytes directly.
	var raw []byte
	for _, h := range hops {
		raw = append(raw, []byte(h.IA)...)
		raw = append(raw, '/')
	}

	return &model.SCIONPath{
		Raw:         raw,
		Hops:        hops,
		Fingerprint: Fingerprint(raw),
	}, nil
}
