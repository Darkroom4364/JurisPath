package dlt

import "time"

// TxStatus represents the lifecycle state of a transaction.
type TxStatus string

const (
	TxPending   TxStatus = "pending"
	TxConfirmed TxStatus = "confirmed"
	TxRejected  TxStatus = "rejected"
)

// MsgType represents the type of consensus message.
type MsgType string

const (
	MsgPropose MsgType = "propose"
	MsgVote    MsgType = "vote"
	MsgCommit  MsgType = "commit"
)

// Transaction represents a token-transfer settlement between two validators.
type Transaction struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`      // validator address
	To        string    `json:"to"`        // validator address
	Amount    int64     `json:"amount"`
	Currency  string    `json:"currency"`
	Status    TxStatus  `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     uint64    `json:"nonce"`
}

// ConsensusMessage is exchanged between validators during consensus rounds.
type ConsensusMessage struct {
	Type        MsgType   `json:"type"`
	TxID        string    `json:"tx_id"`
	ValidatorID string    `json:"validator_id"`
	Round       uint64    `json:"round"`
	Payload     []byte    `json:"payload,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ValidatorState holds a validator's identity and balance sheet.
type ValidatorState struct {
	ID      string           `json:"id"`
	Address string           `json:"address"` // SCION address, e.g. "1-ff00:0:110,[127.0.0.1]:30100"
	Balance map[string]int64 `json:"balance"` // currency -> amount
	Nonce   uint64           `json:"nonce"`
}

// ConsensusResult is returned after a consensus round completes.
type ConsensusResult struct {
	Confirmed bool   `json:"confirmed"`
	Round     uint64 `json:"round"`
	Votes     int    `json:"votes"`
	TxID      string `json:"tx_id"`
}
