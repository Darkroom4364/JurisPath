package scion

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jurispath/jurispath/pkg/model"
)

// MockPathExtractor returns pre-configured hops for testing.
type MockPathExtractor struct{}

// ExtractHops parses hops from JSON-encoded raw bytes (for testing/demo).
func (m *MockPathExtractor) ExtractHops(rawPath []byte) ([]model.ASHop, error) {
	slog.Debug("mock path extractor decoding hops", "raw_len", len(rawPath))
	var hops []model.ASHop
	if err := json.Unmarshal(rawPath, &hops); err != nil {
		slog.Error("mock path decode failed", "error", err)
		return nil, fmt.Errorf("mock path decode: %w", err)
	}
	slog.Debug("mock path decoded", "hops", len(hops))
	return hops, nil
}

// EvidenceMetadata labels mock extractor output as explicit demo evidence.
func (m *MockPathExtractor) EvidenceMetadata(_ []byte, _ []model.ASHop) (string, string) {
	return model.EvidenceClassExplicitDemo, model.ProofStatusUnverified
}

// NewMockPath creates a raw path from a list of hops (JSON-encoded).
func NewMockPath(hops []model.ASHop) ([]byte, error) {
	return json.Marshal(hops)
}
