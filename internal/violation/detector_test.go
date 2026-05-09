package violation

import (
	"testing"
	"time"

	"github.com/jurispath/jurispath/pkg/model"
)

var testPath = &model.SCIONPath{
	Hops: []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
	},
	Fingerprint: "test-fp",
}

func TestDetector_Record(t *testing.T) {
	store := NewMemoryViolationStore()
	det := NewDetector(store)

	offending := []model.ASHop{{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}}
	v := det.Record("tx-1", "policy-1", "traverses unauthorized ISD", testPath, offending)

	if v.ID == "" {
		t.Fatal("violation should have an ID")
	}
	if v.TransactionID != "tx-1" {
		t.Fatalf("expected tx-1, got %s", v.TransactionID)
	}
	if v.PolicyID != "policy-1" {
		t.Fatalf("expected policy-1, got %s", v.PolicyID)
	}
	if v.Severity != "high" {
		t.Fatalf("expected severity 'high' for 1 offending hop, got %s", v.Severity)
	}
	if v.EvidenceClass != model.EvidenceClassExplicitDemo {
		t.Fatalf("EvidenceClass = %q, want %q", v.EvidenceClass, model.EvidenceClassExplicitDemo)
	}
	if v.ProofStatus != model.ProofStatusUnverified {
		t.Fatalf("ProofStatus = %q, want %q", v.ProofStatus, model.ProofStatusUnverified)
	}
	if v.Timestamp.IsZero() {
		t.Fatal("violation should have a timestamp")
	}

	// Verify persisted
	list, err := store.List()
	if err != nil {
		t.Fatalf("listing violations: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(list))
	}
}

func TestDetector_List(t *testing.T) {
	store := NewMemoryViolationStore()
	det := NewDetector(store)

	offending := []model.ASHop{{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}}
	det.Record("tx-1", "p1", "clause-1", testPath, offending)
	det.Record("tx-2", "p1", "clause-2", testPath, offending)

	list, err := det.List()
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(list))
	}
}

func TestDetector_SubscribeUnsubscribe(t *testing.T) {
	store := NewMemoryViolationStore()
	det := NewDetector(store)

	ch := det.Subscribe()

	offending := []model.ASHop{{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}}
	det.Record("tx-1", "p1", "clause", testPath, offending)

	select {
	case v := <-ch:
		if v.TransactionID != "tx-1" {
			t.Fatalf("expected tx-1, got %s", v.TransactionID)
		}
	case <-time.After(time.Second):
		t.Fatal("expected violation event on subscriber channel")
	}

	det.Unsubscribe(ch)

	// Channel should be closed after unsubscribe
	_, ok := <-ch
	if ok {
		t.Fatal("channel should be closed after unsubscribe")
	}
}

func TestDetector_SlowListenerDropsEvent(t *testing.T) {
	store := NewMemoryViolationStore()
	det := NewDetector(store)

	// Subscribe but never read — channel buffer is 64
	ch := det.Subscribe()

	offending := []model.ASHop{{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}}
	// Fill the buffer + 1 to trigger a drop
	for i := 0; i < 65; i++ {
		det.Record("tx", "p1", "clause", testPath, offending)
	}

	// Should not panic — slow listener events are dropped
	det.Unsubscribe(ch)
}

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		count    int
		expected string
	}{
		{0, "medium"},
		{1, "high"},
		{2, "high"},
		{3, "critical"},
		{5, "critical"},
	}

	for _, tt := range tests {
		hops := make([]model.ASHop, tt.count)
		got := classifySeverity(hops)
		if got != tt.expected {
			t.Errorf("classifySeverity(%d hops) = %s, want %s", tt.count, got, tt.expected)
		}
	}
}
