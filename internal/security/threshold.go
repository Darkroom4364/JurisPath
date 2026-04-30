package security

import (
	"crypto/ed25519"
	"fmt"

	"github.com/jurispath/jurispath/pkg/model"
)

// PartialSignature holds a single oracle's signature contribution.
type PartialSignature = model.ThresholdSignature

// OracleInstance represents a single oracle in the threshold group.
type OracleInstance struct {
	ID         string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// ThresholdOracle implements k-of-n threshold signing using independent
// Ed25519 key pairs. At least K oracles must sign for verification to succeed.
type ThresholdOracle struct {
	K       int
	N       int
	Oracles []*OracleInstance
}

// NewThresholdOracle generates N Ed25519 key pairs and creates a threshold
// oracle requiring K-of-N signatures. Returns an error if k > n or k < 1.
func NewThresholdOracle(k, n int) (*ThresholdOracle, error) {
	if k < 1 {
		return nil, fmt.Errorf("threshold k must be >= 1, got %d", k)
	}
	if k > n {
		return nil, fmt.Errorf("threshold k (%d) cannot exceed total n (%d)", k, n)
	}

	oracles := make([]*OracleInstance, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("generating key pair for oracle %d: %w", i, err)
		}
		oracles[i] = &OracleInstance{
			ID:         fmt.Sprintf("oracle-%d", i),
			PrivateKey: priv,
			PublicKey:  pub,
		}
	}

	return &ThresholdOracle{
		K:       k,
		N:       n,
		Oracles: oracles,
	}, nil
}

// PartialSign produces a signature from the oracle at the given index.
func (to *ThresholdOracle) PartialSign(oracleIdx int, data []byte) (PartialSignature, error) {
	if oracleIdx < 0 || oracleIdx >= to.N {
		return PartialSignature{}, fmt.Errorf("oracle index %d out of range [0, %d)", oracleIdx, to.N)
	}

	oracle := to.Oracles[oracleIdx]
	sig := ed25519.Sign(oracle.PrivateKey, data)

	return PartialSignature{
		OracleID:  oracle.ID,
		Signature: sig,
		PublicKey: oracle.PublicKey,
	}, nil
}

// SignThreshold returns K valid partial signatures for receipt issuance.
func (to *ThresholdOracle) SignThreshold(data []byte) ([]model.ThresholdSignature, int, int, error) {
	signatures := make([]model.ThresholdSignature, 0, to.K)
	for i := 0; i < to.K; i++ {
		sig, err := to.PartialSign(i, data)
		if err != nil {
			return nil, 0, 0, err
		}
		signatures = append(signatures, sig)
	}
	return signatures, to.K, to.N, nil
}

// Verify checks that at least K valid signatures exist among the provided
// partial signatures. Each signature is verified against its embedded public
// key, and duplicate oracle IDs are rejected.
func (to *ThresholdOracle) Verify(data []byte, signatures []PartialSignature) (bool, error) {
	if len(signatures) < to.K {
		return false, fmt.Errorf("insufficient signatures: got %d, need at least %d", len(signatures), to.K)
	}

	// Build set of known oracle public keys
	knownKeys := make(map[string]bool)
	for _, o := range to.Oracles {
		knownKeys[string(o.PublicKey)] = true
	}

	seenOracles := make(map[string]bool)
	validCount := 0

	for _, ps := range signatures {
		// Reject duplicate oracle IDs
		if seenOracles[ps.OracleID] {
			continue
		}
		seenOracles[ps.OracleID] = true

		// Verify the key belongs to this threshold group
		if !knownKeys[string(ps.PublicKey)] {
			continue
		}

		// Verify the signature
		if ed25519.Verify(ps.PublicKey, data, ps.Signature) {
			validCount++
		}
	}

	if validCount >= to.K {
		return true, nil
	}

	return false, fmt.Errorf("only %d valid signatures, need at least %d", validCount, to.K)
}
