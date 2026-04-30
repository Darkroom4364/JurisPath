package scion

import (
	"errors"

	"github.com/jurispath/jurispath/pkg/model"
)

const defaultRejectingPathExtractorReason = "API raw_path is not accepted in SCION mode; path evidence must come from authenticated SCION session metadata"

// RejectingPathExtractor fails closed when API callers provide path claims that
// were not observed from authenticated SCION dataplane/session state.
type RejectingPathExtractor struct {
	Reason string
}

// NewRejectingPathExtractor returns a path extractor that rejects every input.
func NewRejectingPathExtractor(reason string) *RejectingPathExtractor {
	if reason == "" {
		reason = defaultRejectingPathExtractorReason
	}
	return &RejectingPathExtractor{Reason: reason}
}

// ExtractHops rejects caller-supplied path bytes in production SCION mode.
func (e *RejectingPathExtractor) ExtractHops(_ []byte) ([]model.ASHop, error) {
	if e.Reason == "" {
		return nil, errors.New(defaultRejectingPathExtractorReason)
	}
	return nil, errors.New(e.Reason)
}
