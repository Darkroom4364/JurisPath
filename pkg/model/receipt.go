package model

import (
	"crypto/ed25519"
	"time"
)

// ComplianceReceipt is a signed attestation that a transaction's network path
// complied with a jurisdiction policy.
type ComplianceReceipt struct {
	ID                  string               `json:"id"`
	TransactionID       string               `json:"transaction_id"`
	PolicyID            string               `json:"policy_id"`
	Path                SCIONPath            `json:"path"`
	ISDProofs           []ISDProof           `json:"isd_proofs"`
	SeqNo               uint64               `json:"seq_no"`
	Timestamp           time.Time            `json:"timestamp"`
	Signature           []byte               `json:"signature"`
	OraclePublicKey     []byte               `json:"oracle_public_key"`
	PreviousHash        []byte               `json:"previous_hash,omitempty"`
	ThresholdK          int                  `json:"threshold_k,omitempty"`
	ThresholdN          int                  `json:"threshold_n,omitempty"`
	ThresholdSignatures []ThresholdSignature `json:"threshold_signatures,omitempty"`
}

// ThresholdSignature holds one oracle's threshold attestation over the same
// canonical payload covered by the receipt's primary oracle signature.
type ThresholdSignature struct {
	OracleID  string            `json:"oracle_id"`
	Signature []byte            `json:"signature"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// ISDProof contains proof of an AS's membership in a specific ISD,
// derived from CP-PKI certificate chains rooted in the ISD's TRC.
type ISDProof struct {
	IA                 string `json:"ia"`
	ISD                uint16 `json:"isd"`
	TRCSerial          uint64 `json:"trc_serial"`
	CertChain          []byte `json:"cert_chain,omitempty"`
	VerificationStatus string `json:"verification_status,omitempty"`
	ProofSource        string `json:"proof_source,omitempty"`
}

// Violation represents a blocked non-compliant path.
type Violation struct {
	ID             string    `json:"id"`
	TransactionID  string    `json:"transaction_id"`
	PolicyID       string    `json:"policy_id"`
	Path           SCIONPath `json:"path"`
	ViolatedClause string    `json:"violated_clause"`
	Severity       string    `json:"severity"` // "critical", "high", "medium"
	OffendingHops  []ASHop   `json:"offending_hops"`
	Timestamp      time.Time `json:"timestamp"`
}

// PolicyResult is the output of a path compliance check.
type PolicyResult struct {
	Compliant bool               `json:"compliant"`
	Receipt   *ComplianceReceipt `json:"receipt,omitempty"`
	Violation *Violation         `json:"violation,omitempty"`
}
