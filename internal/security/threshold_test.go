package security

import (
	"crypto/ed25519"
	"testing"
)

func TestThresholdOracle_KofN_ExactlyK(t *testing.T) {
	to, err := NewThresholdOracle(3, 5)
	if err != nil {
		t.Fatalf("failed to create threshold oracle: %v", err)
	}

	data := []byte("settlement-transaction-42")

	// Collect exactly k=3 signatures
	var sigs []PartialSignature
	for i := 0; i < 3; i++ {
		sig, err := to.PartialSign(i, data)
		if err != nil {
			t.Fatalf("partial sign failed for oracle %d: %v", i, err)
		}
		sigs = append(sigs, sig)
	}

	ok, err := to.Verify(data, sigs)
	if err != nil {
		t.Fatalf("verify should pass with exactly k signatures, got error: %v", err)
	}
	if !ok {
		t.Fatal("verify should return true with exactly k signatures")
	}
}

func TestThresholdOracle_KofN_FailsWithKMinus1(t *testing.T) {
	to, err := NewThresholdOracle(3, 5)
	if err != nil {
		t.Fatalf("failed to create threshold oracle: %v", err)
	}

	data := []byte("settlement-transaction-42")

	// Collect only k-1=2 signatures
	var sigs []PartialSignature
	for i := 0; i < 2; i++ {
		sig, err := to.PartialSign(i, data)
		if err != nil {
			t.Fatalf("partial sign failed: %v", err)
		}
		sigs = append(sigs, sig)
	}

	ok, err := to.Verify(data, sigs)
	if ok {
		t.Fatal("verify should fail with k-1 signatures")
	}
	if err == nil {
		t.Fatal("expected error with insufficient signatures")
	}
}

func TestThresholdOracle_InvalidSignature(t *testing.T) {
	to, err := NewThresholdOracle(2, 3)
	if err != nil {
		t.Fatalf("failed to create threshold oracle: %v", err)
	}

	data := []byte("settlement-transaction-42")

	// One valid signature
	sig0, err := to.PartialSign(0, data)
	if err != nil {
		t.Fatalf("partial sign failed: %v", err)
	}

	// One tampered signature
	tampered := PartialSignature{
		OracleID:  to.Oracles[1].ID,
		Signature: []byte("this-is-not-a-valid-signature-at-all-needs-64-bytes-padding12345678"),
		PublicKey: to.Oracles[1].PublicKey,
	}

	ok, err := to.Verify(data, []PartialSignature{sig0, tampered})
	if ok {
		t.Fatal("verify should fail when one of two required signatures is invalid")
	}
	if err == nil {
		t.Fatal("expected error with invalid signature")
	}
}

func TestThresholdOracle_AllN(t *testing.T) {
	to, err := NewThresholdOracle(3, 5)
	if err != nil {
		t.Fatalf("failed to create threshold oracle: %v", err)
	}

	data := []byte("settlement-transaction-42")

	// Collect all n=5 signatures
	var sigs []PartialSignature
	for i := 0; i < 5; i++ {
		sig, err := to.PartialSign(i, data)
		if err != nil {
			t.Fatalf("partial sign failed: %v", err)
		}
		sigs = append(sigs, sig)
	}

	ok, err := to.Verify(data, sigs)
	if err != nil {
		t.Fatalf("verify should pass with all n signatures, got error: %v", err)
	}
	if !ok {
		t.Fatal("verify should return true with all n signatures")
	}
}

func TestThresholdOracle_ForeignKeyRejected(t *testing.T) {
	to, err := NewThresholdOracle(2, 3)
	if err != nil {
		t.Fatalf("failed to create threshold oracle: %v", err)
	}

	data := []byte("settlement-transaction-42")

	// One valid signature from the group
	sig0, err := to.PartialSign(0, data)
	if err != nil {
		t.Fatalf("partial sign failed: %v", err)
	}

	// One signature from a foreign key (not in the group)
	foreignPub, foreignPriv, _ := ed25519.GenerateKey(nil)
	foreignSig := PartialSignature{
		OracleID:  "foreign-oracle",
		Signature: ed25519.Sign(foreignPriv, data),
		PublicKey: foreignPub,
	}

	ok, err := to.Verify(data, []PartialSignature{sig0, foreignSig})
	if ok {
		t.Fatal("verify should fail when a foreign key is used")
	}
	if err == nil {
		t.Fatal("expected error when foreign key is used")
	}
}
