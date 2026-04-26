package security

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/pkg/model"
)

// ReceiptValidator validates compliance receipts for authenticity, freshness,
// and replay resistance.
type ReceiptValidator struct {
	replayDetector *ReplayDetector
	maxAge         time.Duration
}

// NewReceiptValidator creates a receipt validator with the given maximum
// receipt age and replay detection window.
func NewReceiptValidator(maxAge time.Duration) *ReceiptValidator {
	return &ReceiptValidator{
		replayDetector: NewReplayDetector(maxAge),
		maxAge:         maxAge,
	}
}

// ValidateReceipt checks that a compliance receipt is authentic, fresh,
// and has not been replayed.
func (rv *ReceiptValidator) ValidateReceipt(r *model.ComplianceReceipt) error {
	// Verify cryptographic signature
	valid, err := receipt.Verify(r)
	if err != nil {
		return fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature on receipt %s", r.ID)
	}

	// Check receipt age
	age := time.Since(r.Timestamp)
	if age > rv.maxAge {
		return fmt.Errorf("receipt %s expired: age %v exceeds max %v", r.ID, age, rv.maxAge)
	}

	// Check replay using oracle public key as the fingerprint source
	oracleFingerprint := fmt.Sprintf("%x", r.OraclePublicKey)
	if err := rv.replayDetector.Check(oracleFingerprint, r.SeqNo, r.Timestamp); err != nil {
		return fmt.Errorf("replay check failed for receipt %s: %w", r.ID, err)
	}

	return nil
}

// ValidateReceiptChain validates that a sequence of receipts have consecutive
// sequence numbers from the same oracle, forming a valid chain.
func (rv *ReceiptValidator) ValidateReceiptChain(receipts []*model.ComplianceReceipt) error {
	if len(receipts) == 0 {
		return fmt.Errorf("empty receipt chain")
	}

	for i, r := range receipts {
		// Check consecutive seqNos and hash chain (starting from second receipt)
		if i > 0 {
			prev := receipts[i-1]
			if r.SeqNo != prev.SeqNo+1 {
				return fmt.Errorf(
					"receipt chain broken at index %d: expected seqNo %d, got %d",
					i, prev.SeqNo+1, r.SeqNo,
				)
			}

			// Verify same oracle signed the chain
			if !bytes.Equal(r.OraclePublicKey, prev.OraclePublicKey) {
				return fmt.Errorf(
					"receipt chain broken at index %d: oracle public key changed",
					i,
				)
			}

			// Verify hash chain — PreviousHash should equal sha256(prev.Signature)
			if r.PreviousHash != nil {
				expectedHash := sha256.Sum256(prev.Signature)
				if !bytes.Equal(r.PreviousHash, expectedHash[:]) {
					return fmt.Errorf(
						"receipt chain hash mismatch at index %d: expected %x, got %x",
						i, expectedHash[:], r.PreviousHash,
					)
				}
			}
		}

		// Verify each receipt's signature
		valid, err := receipt.Verify(r)
		if err != nil {
			return fmt.Errorf("receipt %d (%s) signature error: %w", i, r.ID, err)
		}
		if !valid {
			return fmt.Errorf("receipt %d (%s) has invalid signature", i, r.ID)
		}
	}

	return nil
}
