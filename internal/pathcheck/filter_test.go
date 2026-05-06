package pathcheck

import (
	"testing"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

func TestFilterPaths_StrictMode(t *testing.T) {
	pol := &policy.Policy{
		ID:          "test-strict",
		AllowedISDs: []uint16{1, 2},
		Mode:        "strict",
	}
	f := NewPathFilter(pol)

	paths := []model.SCIONPath{
		{
			Fingerprint: "path-a",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
		{
			Fingerprint: "path-b",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
		{
			Fingerprint: "path-c",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
				{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"},
			},
		},
	}

	result := f.FilterPaths(paths)

	if len(result.Compliant) != 2 {
		t.Errorf("expected 2 compliant paths, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 1 {
		t.Errorf("expected 1 non-compliant path, got %d", len(result.NonCompliant))
	}
	if result.NonCompliant[0].Fingerprint != "path-b" {
		t.Errorf("expected non-compliant path to be path-b, got %s", result.NonCompliant[0].Fingerprint)
	}
}

func TestFilterPaths_RelaxedModeFailsClosed(t *testing.T) {
	pol := &policy.Policy{
		ID:          "test-relaxed",
		AllowedISDs: []uint16{1, 2},
		Mode:        "relaxed",
	}
	f := NewPathFilter(pol)

	paths := []model.SCIONPath{
		{
			Fingerprint: "path-a",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
		{
			Fingerprint: "path-b",
			Hops: []model.ASHop{
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
	}

	result := f.FilterPaths(paths)

	if len(result.Compliant) != 0 {
		t.Errorf("expected relaxed mode to fail closed with 0 compliant paths, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 2 {
		t.Errorf("expected all relaxed-mode paths to be non-compliant, got %d", len(result.NonCompliant))
	}
}

func TestFilterPaths_UnknownModeFailsClosed(t *testing.T) {
	pol := &policy.Policy{
		ID:          "test-unknown",
		AllowedISDs: []uint16{1, 2},
		Mode:        "permissive",
	}
	f := NewPathFilter(pol)

	paths := []model.SCIONPath{
		{
			Fingerprint: "allowed-under-strict",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
	}

	result := f.FilterPaths(paths)

	if len(result.Compliant) != 0 {
		t.Errorf("expected unknown mode to fail closed with 0 compliant paths, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 1 {
		t.Errorf("expected unknown mode to mark all paths non-compliant, got %d", len(result.NonCompliant))
	}
}

func TestFilterPaths_EmptyPaths(t *testing.T) {
	pol := &policy.Policy{
		ID:          "test-empty",
		AllowedISDs: []uint16{1},
		Mode:        "strict",
	}
	f := NewPathFilter(pol)

	result := f.FilterPaths([]model.SCIONPath{})

	if len(result.Compliant) != 0 {
		t.Errorf("expected 0 compliant paths, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 0 {
		t.Errorf("expected 0 non-compliant paths, got %d", len(result.NonCompliant))
	}
}

func TestFilterPaths_PathWithNoHops(t *testing.T) {
	pol := &policy.Policy{
		ID:          "test-nohops",
		AllowedISDs: []uint16{1, 2},
		Mode:        "strict",
	}
	f := NewPathFilter(pol)

	paths := []model.SCIONPath{
		{Fingerprint: "empty-path", Hops: []model.ASHop{}},
	}

	result := f.FilterPaths(paths)

	if len(result.Compliant) != 0 {
		t.Errorf("expected 0 compliant, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 1 {
		t.Errorf("expected 1 non-compliant, got %d", len(result.NonCompliant))
	}
}

func TestFilterPaths_UnsupportedModeDoesNotWeakenStrict(t *testing.T) {
	// Unsupported modes fail closed instead of weakening all-hop checks.
	paths := []model.SCIONPath{
		{
			Fingerprint: "transit-isd3",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
	}

	strictPol := &policy.Policy{ID: "strict", AllowedISDs: []uint16{1, 2}, Mode: "strict"}
	relaxedPol := &policy.Policy{ID: "relaxed", AllowedISDs: []uint16{1, 2}, Mode: "relaxed"}

	strictResult := NewPathFilter(strictPol).FilterPaths(paths)
	relaxedResult := NewPathFilter(relaxedPol).FilterPaths(paths)

	if len(strictResult.Compliant) != 0 {
		t.Errorf("strict: expected 0 compliant, got %d", len(strictResult.Compliant))
	}
	if len(strictResult.NonCompliant) != 1 {
		t.Errorf("strict: expected 1 non-compliant, got %d", len(strictResult.NonCompliant))
	}
	if len(relaxedResult.Compliant) != 0 {
		t.Errorf("relaxed: expected 0 compliant, got %d", len(relaxedResult.Compliant))
	}
	if len(relaxedResult.NonCompliant) != 1 {
		t.Errorf("relaxed: expected 1 non-compliant, got %d", len(relaxedResult.NonCompliant))
	}
}
