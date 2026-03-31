package scion

import (
	"encoding/json"
	"fmt"

	"github.com/jurispath/jurispath/pkg/model"
)

// MockPathExtractor returns pre-configured hops for testing.
type MockPathExtractor struct{}

// ExtractHops parses hops from JSON-encoded raw bytes (for testing/demo).
func (m *MockPathExtractor) ExtractHops(rawPath []byte) ([]model.ASHop, error) {
	var hops []model.ASHop
	if err := json.Unmarshal(rawPath, &hops); err != nil {
		return nil, fmt.Errorf("mock path decode: %w", err)
	}
	return hops, nil
}

// NewMockPath creates a raw path from a list of hops (JSON-encoded).
func NewMockPath(hops []model.ASHop) ([]byte, error) {
	return json.Marshal(hops)
}
