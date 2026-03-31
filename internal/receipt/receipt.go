package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/pkg/model"
)

// Generator produces signed compliance receipts.
type Generator struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	seqNo      atomic.Uint64
}

// NewGenerator creates a receipt generator with a fresh Ed25519 key pair.
func NewGenerator() (*Generator, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return &Generator{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// NewGeneratorWithKeys creates a receipt generator with provided keys.
func NewGeneratorWithKeys(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Generator {
	return &Generator{
		privateKey: priv,
		publicKey:  pub,
	}
}

// Issue creates a signed compliance receipt for a compliant transaction.
func (g *Generator) Issue(txID, policyID string, path *model.SCIONPath) (*model.ComplianceReceipt, error) {
	receipt := &model.ComplianceReceipt{
		ID:              uuid.New().String(),
		TransactionID:   txID,
		PolicyID:        policyID,
		Path:            *path,
		SeqNo:           g.seqNo.Add(1),
		Timestamp:       time.Now().UTC(),
		OraclePublicKey: g.publicKey,
	}

	// Build ISD proofs (in production these would come from CP-PKI)
	for _, hop := range path.Hops {
		receipt.ISDProofs = append(receipt.ISDProofs, model.ISDProof{
			IA:  hop.IA,
			ISD: hop.ISD,
		})
	}

	// Sign the receipt
	payload, err := g.marshalForSigning(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshaling receipt for signing: %w", err)
	}
	receipt.Signature = ed25519.Sign(g.privateKey, payload)

	return receipt, nil
}

// Verify checks the Ed25519 signature on a compliance receipt.
func Verify(receipt *model.ComplianceReceipt) (bool, error) {
	g := &Generator{}
	payload, err := g.marshalForSigning(receipt)
	if err != nil {
		return false, fmt.Errorf("marshaling receipt for verification: %w", err)
	}
	return ed25519.Verify(receipt.OraclePublicKey, payload, receipt.Signature), nil
}

func (g *Generator) marshalForSigning(r *model.ComplianceReceipt) ([]byte, error) {
	// Deterministic serialization of the fields that are signed
	signable := struct {
		ID            string            `json:"id"`
		TransactionID string            `json:"transaction_id"`
		PolicyID      string            `json:"policy_id"`
		PathFP        string            `json:"path_fingerprint"`
		SeqNo         uint64            `json:"seq_no"`
		Timestamp     time.Time         `json:"timestamp"`
		ISDProofs     []model.ISDProof  `json:"isd_proofs"`
	}{
		ID:            r.ID,
		TransactionID: r.TransactionID,
		PolicyID:      r.PolicyID,
		PathFP:        r.Path.Fingerprint,
		SeqNo:         r.SeqNo,
		Timestamp:     r.Timestamp,
		ISDProofs:     r.ISDProofs,
	}
	return json.Marshal(signable)
}

// PublicKey returns the oracle's public key.
func (g *Generator) PublicKey() ed25519.PublicKey {
	return g.publicKey
}
