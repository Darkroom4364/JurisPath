package security

import (
	"bytes"
	"fmt"
	"path/filepath"
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

// --- ValidateReceipt (direct) ---

func TestValidateReceipt_Valid(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r := issueTestReceipt(t, gen, "tx-1", "policy-1")
	rv := NewReceiptValidator(5 * time.Minute)
	if err := rv.ValidateReceipt(r); err != nil {
		t.Fatalf("valid receipt should pass: %v", err)
	}
}

func TestValidateReceipt_TamperedSignature(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r.PolicyID = "tampered"

	rv := NewReceiptValidator(5 * time.Minute)
	err = rv.ValidateReceipt(r)
	if err == nil {
		t.Fatal("tampered receipt should fail validation")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestValidateReceipt_Expired(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r := issueTestReceipt(t, gen, "tx-1", "policy-1")

	// Use a very short maxAge so the receipt is already expired
	rv := NewReceiptValidator(1 * time.Nanosecond)
	// Small sleep to guarantee expiration
	time.Sleep(time.Millisecond)
	err = rv.ValidateReceipt(r)
	if err == nil {
		t.Fatal("expired receipt should fail validation")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' error, got: %v", err)
	}
}

func TestValidateReceipt_Replay(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")

	rv := NewReceiptValidator(5 * time.Minute)
	if err := rv.ValidateReceipt(r1); err != nil {
		t.Fatalf("first receipt should pass: %v", err)
	}
	if err := rv.ValidateReceipt(r2); err != nil {
		t.Fatalf("second receipt should pass: %v", err)
	}

	// Replay r1 — same oracle fingerprint + seqNo
	err = rv.ValidateReceipt(r1)
	if err == nil {
		t.Fatal("replayed receipt should fail validation")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected 'replay' error, got: %v", err)
	}
}

// --- ValidateReceiptChain ---

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

func TestValidateReceiptChain_AllowsKeyRotationWithHashContinuity(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	gen, err := receipt.NewGeneratorFromFile(keyPath)
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	if _, err := gen.RotateKeyFile(keyPath); err != nil {
		t.Fatalf("rotating key: %v", err)
	}
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")

	if bytes.Equal(r1.OraclePublicKey, r2.OraclePublicKey) {
		t.Fatal("test setup expected different oracle keys")
	}

	rv := NewReceiptValidator(5 * time.Minute)
	rv.TrustOracleKey(r1.OraclePublicKey)
	rv.TrustOracleKey(r2.OraclePublicKey)
	if err := rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2}); err != nil {
		t.Fatalf("rotated chain with hash continuity should pass: %v", err)
	}
}

func TestValidateReceiptChain_UntrustedKeyRotationRejected(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	gen, err := receipt.NewGeneratorFromFile(keyPath)
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	if _, err := gen.RotateKeyFile(keyPath); err != nil {
		t.Fatalf("rotating key: %v", err)
	}
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")

	rv := NewReceiptValidator(5 * time.Minute)
	rv.TrustOracleKey(r1.OraclePublicKey)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2})
	if err == nil {
		t.Fatal("untrusted rotated chain should fail")
	}
	if !strings.Contains(err.Error(), "trusted rotation") {
		t.Fatalf("expected trusted rotation error, got: %v", err)
	}
}

func TestValidateReceiptChain_RotationHashMismatchRejected(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	gen, err := receipt.NewGeneratorFromFile(keyPath)
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	if _, err := gen.RotateKeyFile(keyPath); err != nil {
		t.Fatalf("rotating key: %v", err)
	}
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")
	r2.PreviousHash = []byte("wrong-rotation-boundary-hash")

	rv := NewReceiptValidator(5 * time.Minute)
	rv.TrustOracleKey(r1.OraclePublicKey)
	rv.TrustOracleKey(r2.OraclePublicKey)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2})
	if err == nil {
		t.Fatal("rotated chain with hash mismatch should fail")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected 'hash mismatch' error, got: %v", err)
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
	r2.PreviousHash = []byte("tampered-hash-value-that-is-wrong")

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

func TestValidateReceiptChain_NilPreviousHashRejected(t *testing.T) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	r1 := issueTestReceipt(t, gen, "tx-1", "policy-1")
	r2 := issueTestReceipt(t, gen, "tx-2", "policy-1")

	// Strip PreviousHash from non-genesis receipt
	r2.PreviousHash = nil

	rv := NewReceiptValidator(5 * time.Minute)
	err = rv.ValidateReceiptChain([]*model.ComplianceReceipt{r1, r2})
	if err == nil {
		t.Fatal("nil PreviousHash on non-genesis receipt should be rejected")
	}
	if !strings.Contains(err.Error(), "PreviousHash is nil") {
		t.Fatalf("expected 'PreviousHash is nil' error, got: %v", err)
	}
}
