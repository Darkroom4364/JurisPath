package security

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/pkg/model"
)

func issueTestReceipt(t *testing.T, gen *receipt.Generator, txID, policyID string) *model.ComplianceReceipt {
	t.Helper()
	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
			{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"},
		},
		Fingerprint: fmt.Sprintf("fp-%s", txID),
		Raw:         []byte(txID),
	}
	rcpt, err := gen.Issue(txID, policyID, path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}
	return rcpt
}

func TestValidateReceiptChain_Valid(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")
	r3 := issueTestReceipt(t, gen, "tx-3", "policy-1")

	rv := NewReceiptValidator(5 * time.Minute)
	if err := rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2, r3}); err != nil {
		t.Fatalf("valid chain should pass: %v", err)
	}
}

func TestValidateReceiptChain_HashMismatch(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")
	r3 := issueTestReceipt(t, gen, "tx-3", "policy-1")

	// Tamper with r2's PreviousHash
	if r2.PreviousHash != nil {
		r2.PreviousHash = []byte("tampered-hash-value-that-is-wrong")
	} else {
		// If Phase 3a isn't done yet, manually set a wrong hash to test validation
		r2.PreviousHash = []byte("tampered-hash-value-that-is-wrong")
	}

	rv := NewReceiptValidator(5 * time.Minute)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2, r3})
	if err == nil {
		t.Fatal("chain with tampered hash should fail")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected 'hash mismatch' error, got: %v", err)
	}
}

func TestValidateReceiptChain_TamperSignedField(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")
	r3 := issueTestReceipt(t, gen, "tx-3", "policy-1")

	// Tamper with r2's PolicyID (invalidates signature)
	r2.PolicyID = "tampered-policy"

	rv := NewReceiptValidator(5 * time.Minute)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2, r3})
	if err == nil {
		t.Fatal("chain with tampered signed field should fail")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestValidateReceiptChain_SwapOrder(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")
	r3 := issueTestReceipt(t, gen, "tx-3", "policy-1")

	// Swap positions 1 and 2
	rv := NewReceiptValidator(5 * time.Minute)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r3, r2})
	if err == nil {
		t.Fatal("chain with swapped receipts should fail")
	}
}

func TestValidateReceiptChain_GenesisNilHash(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	// Ensure genesis receipt has nil PreviousHash
	r1.PreviousHash = nil

	rv := NewReceiptValidator(5 * time.Minute)
	if err := rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1}); err != nil {
		t.Fatalf("single genesis receipt should pass: %v", err)
	}
}

// Ensure sha256 import is used (compile guard)
var _ = sha256.Sum256
