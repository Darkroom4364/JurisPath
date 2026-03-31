package scion

import (
	"crypto/sha256"
	"fmt"

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
