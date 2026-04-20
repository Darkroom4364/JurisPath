package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/pkg/model"
)

var keyMagic = []byte{0x4A, 0x50, 0x53, 0x4B} // "JPSK"

// Generator produces signed compliance receipts.
type Generator struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	mu         sync.Mutex
	seqNo      uint64
	lastHash   []byte // sha256 of previous receipt's signature
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

// NewGeneratorFromFile loads or generates an oracle key from the given file path.
func NewGeneratorFromFile(path string) (*Generator, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != 36 {
			return nil, fmt.Errorf("invalid oracle key file: expected 36 bytes, got %d", len(data))
		}
		if !bytes.Equal(data[:4], keyMagic) {
			return nil, fmt.Errorf("invalid oracle key file: bad magic bytes")
		}

		info, err := os.Stat(path)
		if err == nil && info.Mode().Perm() > 0600 {
			slog.Warn("oracle key file has permissive permissions", "path", path, "mode", fmt.Sprintf("%o", info.Mode().Perm()))
		}

		seed := data[4:]
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		slog.Info("oracle key loaded from file", "path", path)
		return NewGeneratorWithKeys(priv, pub), nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading oracle key file: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".oracle-key-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp key file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var buf []byte
	buf = append(buf, keyMagic...)
	buf = append(buf, priv.Seed()...)

	if _, err := tmpFile.Write(buf); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("writing oracle key: %w", err)
	}
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("setting key file permissions: %w", err)
	}
	tmpFile.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("renaming key file: %w", err)
	}

	slog.Info("oracle key generated and saved", "path", path)
	return NewGeneratorWithKeys(priv, pub), nil
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
	g.mu.Lock()
	defer g.mu.Unlock()

	g.seqNo++
	receipt := &model.ComplianceReceipt{
		ID:              uuid.New().String(),
		TransactionID:   txID,
		PolicyID:        policyID,
		Path:            *path,
		SeqNo:           g.seqNo,
		Timestamp:       time.Now().UTC(),
		OraclePublicKey: g.publicKey,
		PreviousHash:    g.lastHash,
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

	// Update chain state
	h := sha256.Sum256(receipt.Signature)
	g.lastHash = h[:]

	return receipt, nil
}

// SeedChain restores the hash chain state from the receipt store on startup.
// If the last receipt was signed by a different oracle key, starts a new chain
// but continues the sequence number to avoid collisions.
func (g *Generator) SeedChain(store Store) error {
	last, err := store.Last()
	if err != nil {
		return fmt.Errorf("loading last receipt for chain seeding: %w", err)
	}
	if last == nil {
		// Empty store — genesis state
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Continue sequence numbering regardless of key match
	g.seqNo = last.SeqNo

	// Check if the last receipt was signed by this oracle
	if !bytes.Equal(last.OraclePublicKey, g.publicKey) {
		slog.Warn("last receipt signed by different oracle key — starting new chain",
			"last_seq", last.SeqNo)
		// Keep seqNo to avoid collision, but reset lastHash (new chain)
		return nil
	}

	// Same key — continue the chain
	h := sha256.Sum256(last.Signature)
	g.lastHash = h[:]
	slog.Info("hash chain seeded from store", "seq_no", last.SeqNo)
	return nil
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
		ID            string           `json:"id"`
		TransactionID string           `json:"transaction_id"`
		PolicyID      string           `json:"policy_id"`
		PathFP        string           `json:"path_fingerprint"`
		SeqNo         uint64           `json:"seq_no"`
		Timestamp     time.Time        `json:"timestamp"`
		ISDProofs     []model.ISDProof `json:"isd_proofs"`
		PreviousHash  []byte           `json:"previous_hash,omitempty"`
	}{
		ID:            r.ID,
		TransactionID: r.TransactionID,
		PolicyID:      r.PolicyID,
		PathFP:        r.Path.Fingerprint,
		SeqNo:         r.SeqNo,
		Timestamp:     r.Timestamp,
		ISDProofs:     r.ISDProofs,
		PreviousHash:  r.PreviousHash,
	}
	return json.Marshal(signable)
}

// PublicKey returns the oracle's public key.
func (g *Generator) PublicKey() ed25519.PublicKey {
	return g.publicKey
}
