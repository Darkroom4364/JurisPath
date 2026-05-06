package pathcheck

import (
	"testing"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

func TestChecker_Compliant(t *testing.T) {
	p := &policy.Policy{
		ID:          "test-v1",
		AllowedISDs: []uint16{1, 2},
		Mode:        "strict",
	}
	c := NewChecker(p)

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}

	result, err := c.Check(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Compliant {
		t.Errorf("expected compliant, got violation: %s", result.ViolatedClause)
	}
}

func TestChecker_Violation(t *testing.T) {
	p := &policy.Policy{
		ID:          "test-v1",
		AllowedISDs: []uint16{1, 2},
		Mode:        "strict",
	}
	c := NewChecker(p)

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}, // unauthorized
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}

	result, err := c.Check(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Compliant {
		t.Error("expected violation, got compliant")
	}
	if len(result.OffendingHops) != 1 {
		t.Errorf("expected 1 offending hop, got %d", len(result.OffendingHops))
	}
	if result.OffendingHops[0].ISD != 3 {
		t.Errorf("expected offending ISD 3, got %d", result.OffendingHops[0].ISD)
	}
}

func TestChecker_RelaxedModeFailsClosed(t *testing.T) {
	p := &policy.Policy{
		ID:          "relaxed-v1",
		AllowedISDs: []uint16{1, 2},
		Mode:        "relaxed",
	}
	c := NewChecker(p)

	// Path transits ISD-3 in the middle but endpoints are in allowed ISDs
	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}

	result, err := c.Check(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Compliant {
		t.Fatal("relaxed mode must fail closed")
	}
	if len(result.OffendingHops) != len(path.Hops) {
		t.Fatalf("expected all hops to be marked offending, got %d", len(result.OffendingHops))
	}
	if result.ViolatedClause != `unsupported policy mode "relaxed"; failing closed` {
		t.Fatalf("unexpected violated clause: %q", result.ViolatedClause)
	}
}

func TestChecker_UnknownModeFailsClosed(t *testing.T) {
	p := &policy.Policy{
		ID:          "unknown-v1",
		AllowedISDs: []uint16{1, 2},
		Mode:        "permissive",
	}
	c := NewChecker(p)

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}

	result, err := c.Check(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Compliant {
		t.Fatal("unknown mode must fail closed")
	}
	if len(result.OffendingHops) != len(path.Hops) {
		t.Fatalf("expected all hops to be marked offending, got %d", len(result.OffendingHops))
	}
}

func TestChecker_EmptyPath(t *testing.T) {
	p := &policy.Policy{
		ID:          "test-v1",
		AllowedISDs: []uint16{1},
		Mode:        "strict",
	}
	c := NewChecker(p)

	path := &model.SCIONPath{Hops: []model.ASHop{}}
	_, err := c.Check(path)
	if err == nil {
		t.Error("expected error for empty path")
	}
}
