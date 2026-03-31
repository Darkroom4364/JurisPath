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

func TestFilterPaths_RelaxedMode(t *testing.T) {
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

	// In relaxed mode, path-a is compliant (endpoints in ISDs 1,2) even though
	// it transits ISD-3. path-b is non-compliant because the first hop is ISD-3.
	if len(result.Compliant) != 1 {
		t.Errorf("expected 1 compliant path, got %d", len(result.Compliant))
	}
	if len(result.NonCompliant) != 1 {
		t.Errorf("expected 1 non-compliant path, got %d", len(result.NonCompliant))
	}
	if result.Compliant[0].Fingerprint != "path-a" {
		t.Errorf("expected compliant path to be path-a, got %s", result.Compliant[0].Fingerprint)
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

func TestFilterPaths_StrictVsRelaxed(t *testing.T) {
	// Same paths, different modes should yield different results.
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
	if len(relaxedResult.Compliant) != 1 {
		t.Errorf("relaxed: expected 1 compliant, got %d", len(relaxedResult.Compliant))
	}
	if len(relaxedResult.NonCompliant) != 0 {
		t.Errorf("relaxed: expected 0 non-compliant, got %d", len(relaxedResult.NonCompliant))
	}
}
