package pathcheck

import (
	"testing"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

func TestCheckHopsCompliant_UnknownModeFailsClosed(t *testing.T) {
	hops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
	}

	offending := CheckHopsCompliant(hops, []uint16{1, 2}, "permissive")

	if len(offending) != len(hops) {
		t.Fatalf("expected unknown mode to mark all hops offending, got %d", len(offending))
	}
	for i := range hops {
		if offending[i].IA != hops[i].IA || offending[i].ISD != hops[i].ISD || offending[i].AS != hops[i].AS {
			t.Fatalf("offending[%d] = %+v, want %+v", i, offending[i], hops[i])
		}
	}
}

func TestCheckHopsCompliant_StrictRejectsUnauthorizedTransit(t *testing.T) {
	hops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
	}

	offending := CheckHopsCompliant(hops, []uint16{1, 2}, "strict")

	if len(offending) != 1 {
		t.Fatalf("expected one offending transit hop, got %d", len(offending))
	}
	if offending[0].ISD != 3 {
		t.Fatalf("offending ISD = %d, want 3", offending[0].ISD)
	}
}

func TestCheckerAndFilterParity_FailClosed(t *testing.T) {
	path := model.SCIONPath{
		Fingerprint: "transit-isd3",
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}
	pol := &policy.Policy{ID: "strict", AllowedISDs: []uint16{1, 2}, Mode: policy.ModeStrict}

	checkResult, err := NewChecker(pol).Check(&path)
	if err != nil {
		t.Fatalf("checker returned error: %v", err)
	}
	if checkResult.Compliant {
		t.Fatal("checker marked unauthorized transit path compliant")
	}

	filterResult := NewPathFilter(pol).FilterPaths([]model.SCIONPath{path})
	if len(filterResult.Compliant) != 0 || len(filterResult.NonCompliant) != 1 {
		t.Fatalf("filter result = %+v, want one non-compliant path", filterResult)
	}
}

func TestCheckerAndFilterParity_UnknownModeFailsClosed(t *testing.T) {
	path := model.SCIONPath{
		Fingerprint: "allowed-under-strict",
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
	}
	pol := &policy.Policy{ID: "unsupported", AllowedISDs: []uint16{1, 2}, Mode: "permissive"}

	checkResult, err := NewChecker(pol).Check(&path)
	if err != nil {
		t.Fatalf("checker returned error: %v", err)
	}
	if checkResult.Compliant {
		t.Fatal("checker marked unsupported-mode path compliant")
	}

	filterResult := NewPathFilter(pol).FilterPaths([]model.SCIONPath{path})
	if len(filterResult.Compliant) != 0 || len(filterResult.NonCompliant) != 1 {
		t.Fatalf("filter result = %+v, want one non-compliant path", filterResult)
	}
}
