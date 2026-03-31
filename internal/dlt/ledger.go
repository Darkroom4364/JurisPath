package dlt

import (
	"fmt"
	"sync"
	"time"
)

// Ledger is a mutex-protected DLT state machine that tracks validators,
// balances, and transactions.
type Ledger struct {
	mu           sync.RWMutex
	validators   map[string]*ValidatorState // id -> state
	pending      map[string]*Transaction    // txID -> tx
	confirmed    map[string]*Transaction    // txID -> tx
	allTxs       []*Transaction             // ordered history
	currentRound uint64
}

// NewLedger creates a ledger seeded with the given validator states.
func NewLedger(validators []ValidatorState) *Ledger {
	l := &Ledger{
		validators: make(map[string]*ValidatorState, len(validators)),
		pending:    make(map[string]*Transaction),
		confirmed:  make(map[string]*Transaction),
	}
	for i := range validators {
		v := validators[i]
		// Deep-copy balance map so callers can't mutate ledger state.
		bal := make(map[string]int64, len(v.Balance))
		for k, amt := range v.Balance {
			bal[k] = amt
		}
		l.validators[v.ID] = &ValidatorState{
			ID:      v.ID,
			Address: v.Address,
			Balance: bal,
			Nonce:   v.Nonce,
		}
	}
	return l
}

// SubmitTransaction validates the sender's balance and adds the transaction
// to the pending pool. It does NOT yet debit funds; that happens at commit.
func (l *Ledger) SubmitTransaction(tx *Transaction) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	sender, ok := l.validators[tx.From]
	if !ok {
		return fmt.Errorf("unknown sender validator: %s", tx.From)
	}
	if _, ok := l.validators[tx.To]; !ok {
		return fmt.Errorf("unknown recipient validator: %s", tx.To)
	}
	if tx.Amount <= 0 {
		return fmt.Errorf("amount must be positive, got %d", tx.Amount)
	}
	if sender.Balance[tx.Currency] < tx.Amount {
		return fmt.Errorf("insufficient %s balance: have %d, need %d",
			tx.Currency, sender.Balance[tx.Currency], tx.Amount)
	}

	tx.Status = TxPending
	tx.Nonce = sender.Nonce + 1
	tx.Timestamp = time.Now()
	l.pending[tx.ID] = tx
	l.allTxs = append(l.allTxs, tx)
	return nil
}

// ProposeBlock creates a proposal message for the next pending transaction.
func (l *Ledger) ProposeBlock(validatorID string) (*ConsensusMessage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.validators[validatorID]; !ok {
		return nil, fmt.Errorf("unknown proposer: %s", validatorID)
	}

	// Pick the first pending transaction.
	var target *Transaction
	for _, tx := range l.pending {
		target = tx
		break
	}
	if target == nil {
		return nil, fmt.Errorf("no pending transactions to propose")
	}

	l.currentRound++
	return &ConsensusMessage{
		Type:        MsgPropose,
		TxID:        target.ID,
		ValidatorID: validatorID,
		Round:       l.currentRound,
		Timestamp:   time.Now(),
	}, nil
}

// Vote validates a proposal and returns a vote message. A validator votes
// yes only if the sender has sufficient balance at vote time.
func (l *Ledger) Vote(msg *ConsensusMessage) (*ConsensusMessage, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if msg.Type != MsgPropose {
		return nil, fmt.Errorf("expected propose message, got %s", msg.Type)
	}
	tx, ok := l.pending[msg.TxID]
	if !ok {
		return nil, fmt.Errorf("transaction %s not in pending pool", msg.TxID)
	}

	sender, ok := l.validators[tx.From]
	if !ok {
		return nil, fmt.Errorf("unknown sender validator: %s", tx.From)
	}

	// Vote yes if balance is sufficient, otherwise vote no via nil payload.
	var payload []byte
	if sender.Balance[tx.Currency] >= tx.Amount {
		payload = []byte("yes")
	} else {
		payload = []byte("no")
	}

	return &ConsensusMessage{
		Type:        MsgVote,
		TxID:        msg.TxID,
		ValidatorID: msg.ValidatorID,
		Round:       msg.Round,
		Payload:     payload,
		Timestamp:   time.Now(),
	}, nil
}

// Commit applies a confirmed transaction to ledger state: debits the sender,
// credits the recipient, and moves the transaction from pending to confirmed.
func (l *Ledger) Commit(msg *ConsensusMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, ok := l.pending[msg.TxID]
	if !ok {
		return fmt.Errorf("transaction %s not in pending pool", msg.TxID)
	}

	sender := l.validators[tx.From]
	recipient := l.validators[tx.To]

	if sender.Balance[tx.Currency] < tx.Amount {
		tx.Status = TxRejected
		delete(l.pending, tx.ID)
		return fmt.Errorf("insufficient balance at commit time")
	}

	sender.Balance[tx.Currency] -= tx.Amount
	recipient.Balance[tx.Currency] += tx.Amount
	sender.Nonce++

	tx.Status = TxConfirmed
	delete(l.pending, tx.ID)
	l.confirmed[tx.ID] = tx
	return nil
}

// GetBalance returns the balance for a given validator and currency.
func (l *Ledger) GetBalance(validatorID, currency string) int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()

	v, ok := l.validators[validatorID]
	if !ok {
		return 0
	}
	return v.Balance[currency]
}

// GetTransaction returns a transaction by ID, or nil if not found.
func (l *Ledger) GetTransaction(txID string) *Transaction {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if tx, ok := l.confirmed[txID]; ok {
		return tx
	}
	if tx, ok := l.pending[txID]; ok {
		return tx
	}
	return nil
}

// ListTransactions returns all transactions in submission order.
func (l *Ledger) ListTransactions() []*Transaction {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]*Transaction, len(l.allTxs))
	copy(out, l.allTxs)
	return out
}

// GetValidators returns a snapshot of all validator states.
func (l *Ledger) GetValidators() []ValidatorState {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]ValidatorState, 0, len(l.validators))
	for _, v := range l.validators {
		bal := make(map[string]int64, len(v.Balance))
		for k, amt := range v.Balance {
			bal[k] = amt
		}
		out = append(out, ValidatorState{
			ID:      v.ID,
			Address: v.Address,
			Balance: bal,
			Nonce:   v.Nonce,
		})
	}
	return out
}

// CurrentRound returns the current consensus round number.
func (l *Ledger) CurrentRound() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.currentRound
}
