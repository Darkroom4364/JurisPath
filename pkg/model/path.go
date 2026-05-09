package model

const (
	// EvidenceClassExplicitDemo means path metadata was supplied directly to
	// the API/CLI demo surface rather than observed from a SCION session.
	EvidenceClassExplicitDemo = "explicit-demo"
	// EvidenceClassSCIONObserved means path metadata was derived from SCION
	// session/dataplane state rather than caller-supplied path claims.
	EvidenceClassSCIONObserved = "scion-observed"

	ProofStatusUnverified = "unverified"
	ProofStatusVerified   = "verified"
	ProofStatusMixed      = "mixed"
	ProofStatusObserved   = "observed"
)

// ASHop represents a single AS-level hop in a SCION path.
type ASHop struct {
	IA     string `json:"ia"`                // ISD-AS identifier (e.g., "1-ff00:0:110")
	ISD    uint16 `json:"isd"`               // Isolation Domain number
	AS     string `json:"as"`                // AS number within the ISD
	HopMAC []byte `json:"hop_mac,omitempty"` // SCION hop field MAC (6 bytes), if available
}

// SCIONPath represents an extracted and normalized SCION path.
type SCIONPath struct {
	Raw           []byte  `json:"raw,omitempty"`
	Hops          []ASHop `json:"hops"`
	Fingerprint   string  `json:"fingerprint"`
	EvidenceClass string  `json:"evidence_class,omitempty"`
	ProofStatus   string  `json:"proof_status,omitempty"`
}

func NormalizeEvidenceClass(value string) string {
	if value != "" {
		return value
	}
	return EvidenceClassExplicitDemo
}

func NormalizeProofStatus(value string) string {
	if value != "" {
		return value
	}
	return ProofStatusUnverified
}
