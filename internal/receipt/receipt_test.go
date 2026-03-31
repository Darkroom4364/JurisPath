package receipt

import (
	"testing"

	"github.com/jurispath/jurispath/pkg/model"
)

func TestGenerator_IssueAndVerify(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
		Fingerprint: "abc123",
	}

	rcpt, err := gen.Issue("tx-001", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}

	if rcpt.TransactionID != "tx-001" {
		t.Errorf("expected tx-001, got %s", rcpt.TransactionID)
	}
	if rcpt.SeqNo != 1 {
		t.Errorf("expected seq 1, got %d", rcpt.SeqNo)
	}
	if len(rcpt.Signature) == 0 {
		t.Error("signature should not be empty")
	}

	// Verify signature
	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying receipt: %v", err)
	}
	if !valid {
		t.Error("receipt signature should be valid")
	}

	// Tamper and verify again
	rcpt.TransactionID = "tx-tampered"
	valid, _ = Verify(rcpt)
	if valid {
		t.Error("tampered receipt should not verify")
	}
}

func TestGenerator_SequenceNumbers(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	path := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "test",
	}

	r1, _ := gen.Issue("tx-1", "p1", path)
	r2, _ := gen.Issue("tx-2", "p1", path)

	if r2.SeqNo <= r1.SeqNo {
		t.Errorf("sequence numbers must be monotonically increasing: %d <= %d", r2.SeqNo, r1.SeqNo)
	}
}
