package scion

import (
	"crypto/sha256"
	"fmt"

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
	hops, err := extractor.ExtractHops(raw)
	if err != nil {
		return nil, fmt.Errorf("extracting hops: %w", err)
	}
	return &model.SCIONPath{
		Raw:         raw,
		Hops:        hops,
		Fingerprint: Fingerprint(raw),
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

// ExtractHops implements PathExtractor for raw bytes. It first tries to
// decode the binary path metadata format (produced by SerializeSnetPath).
// If that fails, it falls back to JSON-encoded hops for backward
// compatibility with dev/test clients.
func (e *SnetPathExtractor) ExtractHops(rawPath []byte) ([]model.ASHop, error) {
	if len(rawPath) >= 3 && rawPath[0] == pathMetaVersion {
		return decodeSnetPathMeta(rawPath)
	}
	// Fallback: JSON-encoded mock format for backward compatibility.
	mock := &MockPathExtractor{}
	return mock.ExtractHops(rawPath)
}

// ExtractHopsFromSnetPath reads path.Metadata().Interfaces and extracts
// unique ISD-AS hops in the order they appear along the path.
func (e *SnetPathExtractor) ExtractHopsFromSnetPath(p snet.Path) ([]model.ASHop, error) {
	meta := p.Metadata()
	if meta == nil {
		return nil, fmt.Errorf("path metadata is nil")
	}

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
		return nil, fmt.Errorf("no hops found in path metadata")
	}

	return hops, nil
}

// BuildSCIONPathFromSnet constructs a model.SCIONPath from a real snet.Path.
// It uses SerializeSnetPath for the Raw field so that fingerprints are
// consistent with paths decoded via BuildSCIONPath + ExtractHops.
func BuildSCIONPathFromSnet(extractor *SnetPathExtractor, p snet.Path) (*model.SCIONPath, error) {
	hops, err := extractor.ExtractHopsFromSnetPath(p)
	if err != nil {
		return nil, fmt.Errorf("extracting hops from snet path: %w", err)
	}

	raw, err := SerializeSnetPath(p)
	if err != nil {
		return nil, fmt.Errorf("serializing snet path: %w", err)
	}

	return &model.SCIONPath{
		Raw:         raw,
		Hops:        hops,
		Fingerprint: Fingerprint(raw),
	}, nil
}
