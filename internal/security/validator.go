package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/pkg/model"
)

// ReceiptValidator validates compliance receipts for authenticity, freshness,
// and replay resistance.
type ReceiptValidator struct {
	replayDetector *ReplayDetector
	maxAge         time.Duration
	trustedKeysMu  sync.RWMutex
	trustedKeys    map[string]struct{}
	thresholdMu    sync.RWMutex
	thresholdKeys  map[string]struct{}
}

// NewReceiptValidator creates a receipt validator with the given maximum
// receipt age and replay detection window.
func NewReceiptValidator(maxAge time.Duration) *ReceiptValidator {
	return &ReceiptValidator{
		replayDetector: NewReplayDetector(maxAge),
		maxAge:         maxAge,
	}
}

// TrustOracleKey marks an oracle public key as trusted for receipt and chain
// validation. When any trusted keys are configured, receipts from unknown keys
// are rejected.
func (rv *ReceiptValidator) TrustOracleKey(key []byte) {
	rv.trustedKeysMu.Lock()
	defer rv.trustedKeysMu.Unlock()
	if rv.trustedKeys == nil {
		rv.trustedKeys = make(map[string]struct{})
	}
	rv.trustedKeys[string(key)] = struct{}{}
}

// TrustThresholdOracleKey marks a threshold oracle public key as trusted.
// When any threshold keys are configured, threshold attestations from unknown
// keys are rejected.
func (rv *ReceiptValidator) TrustThresholdOracleKey(key []byte) {
	rv.thresholdMu.Lock()
	defer rv.thresholdMu.Unlock()
	if rv.thresholdKeys == nil {
		rv.thresholdKeys = make(map[string]struct{})
	}
	rv.thresholdKeys[string(key)] = struct{}{}
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
	if !rv.isTrustedKey(r.OraclePublicKey) {
		return fmt.Errorf("untrusted oracle key on receipt %s", r.ID)
	}
	if err := rv.validateThresholdAttestations(r); err != nil {
		return err
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
// sequence numbers and a valid signature hash chain. Oracle key rotation is
// allowed when hash continuity is preserved across the key boundary and both
// adjacent oracle keys are trusted.
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

			// Verify hash chain — PreviousHash must be non-nil and equal sha256(prev.Signature)
			if r.PreviousHash == nil {
				return fmt.Errorf(
					"receipt chain broken at index %d: PreviousHash is nil",
					i,
				)
			}
			expectedHash := sha256.Sum256(prev.Signature)
			if !bytes.Equal(r.PreviousHash, expectedHash[:]) {
				return fmt.Errorf(
					"receipt chain hash mismatch at index %d: expected %x, got %x",
					i, expectedHash[:], r.PreviousHash,
				)
			}
			if !bytes.Equal(r.OraclePublicKey, prev.OraclePublicKey) {
				if !rv.isTrustedKey(prev.OraclePublicKey) || !rv.isTrustedKey(r.OraclePublicKey) {
					return fmt.Errorf(
						"receipt chain broken at index %d: oracle public key changed without trusted rotation",
						i,
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
		if !rv.isTrustedKey(r.OraclePublicKey) {
			return fmt.Errorf("receipt %d (%s) uses untrusted oracle key", i, r.ID)
		}
		if err := rv.validateThresholdAttestations(r); err != nil {
			return fmt.Errorf("receipt %d (%s) threshold validation failed: %w", i, r.ID, err)
		}
	}

	return nil
}

func (rv *ReceiptValidator) validateThresholdAttestations(r *model.ComplianceReceipt) error {
	if r.ThresholdK == 0 && r.ThresholdN == 0 && len(r.ThresholdSignatures) == 0 {
		return nil
	}
	if r.ThresholdK < 1 {
		return fmt.Errorf("receipt %s has invalid threshold_k %d", r.ID, r.ThresholdK)
	}
	if r.ThresholdN < 1 {
		return fmt.Errorf("receipt %s has invalid threshold_n %d", r.ID, r.ThresholdN)
	}
	if r.ThresholdK > r.ThresholdN {
		return fmt.Errorf("receipt %s threshold_k %d exceeds threshold_n %d", r.ID, r.ThresholdK, r.ThresholdN)
	}
	if len(r.ThresholdSignatures) < r.ThresholdK {
		return fmt.Errorf("receipt %s has insufficient threshold signatures: got %d, need %d", r.ID, len(r.ThresholdSignatures), r.ThresholdK)
	}
	if len(r.ThresholdSignatures) > r.ThresholdN {
		return fmt.Errorf("receipt %s has too many threshold signatures: got %d, group size %d", r.ID, len(r.ThresholdSignatures), r.ThresholdN)
	}

	payload, err := receipt.SigningPayload(r)
	if err != nil {
		return fmt.Errorf("threshold signing payload error for receipt %s: %w", r.ID, err)
	}

	seen := make(map[string]struct{}, len(r.ThresholdSignatures))
	for _, sig := range r.ThresholdSignatures {
		if sig.OracleID == "" {
			return fmt.Errorf("receipt %s has threshold signature with empty oracle_id", r.ID)
		}
		if _, ok := seen[sig.OracleID]; ok {
			return fmt.Errorf("receipt %s has duplicate threshold signature from oracle %s", r.ID, sig.OracleID)
		}
		seen[sig.OracleID] = struct{}{}
		if len(sig.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("receipt %s threshold signature from oracle %s has invalid public key length", r.ID, sig.OracleID)
		}
		if !rv.isTrustedThresholdKey(sig.PublicKey) {
			return fmt.Errorf("receipt %s threshold signature from oracle %s uses untrusted key", r.ID, sig.OracleID)
		}
		if !ed25519.Verify(sig.PublicKey, payload, sig.Signature) {
			return fmt.Errorf("receipt %s threshold signature from oracle %s is invalid", r.ID, sig.OracleID)
		}
	}

	return nil
}

func (rv *ReceiptValidator) isTrustedKey(key []byte) bool {
	rv.trustedKeysMu.RLock()
	defer rv.trustedKeysMu.RUnlock()
	if len(rv.trustedKeys) == 0 {
		return true
	}
	_, ok := rv.trustedKeys[string(key)]
	return ok
}

func (rv *ReceiptValidator) isTrustedThresholdKey(key []byte) bool {
	rv.thresholdMu.RLock()
	defer rv.thresholdMu.RUnlock()
	if len(rv.thresholdKeys) == 0 {
		return true
	}
	_, ok := rv.thresholdKeys[string(key)]
	return ok
}
