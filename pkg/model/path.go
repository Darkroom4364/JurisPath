package model

// ASHop represents a single AS-level hop in a SCION path.
type ASHop struct {
	IA     string `json:"ia"`               // ISD-AS identifier (e.g., "1-ff00:0:110")
	ISD    uint16 `json:"isd"`              // Isolation Domain number
	AS     string `json:"as"`               // AS number within the ISD
	HopMAC []byte `json:"hop_mac,omitempty"` // SCION hop field MAC (6 bytes), if available
}

// SCIONPath represents an extracted and normalized SCION path.
type SCIONPath struct {
	Raw         []byte  `json:"raw,omitempty"`
	Hops        []ASHop `json:"hops"`
	Fingerprint string  `json:"fingerprint"`
}
