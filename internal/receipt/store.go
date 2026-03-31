package receipt

import (
	"sync"

	"github.com/jurispath/jurispath/pkg/model"
)

// Store is an in-memory receipt store with append-only semantics.
type Store struct {
	mu       sync.RWMutex
	receipts []*model.ComplianceReceipt
	byTxID   map[string]*model.ComplianceReceipt
}

// NewStore creates an empty receipt store.
func NewStore() *Store {
	return &Store{
		byTxID: make(map[string]*model.ComplianceReceipt),
	}
}

// Append adds a receipt to the store.
func (s *Store) Append(r *model.ComplianceReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, r)
	s.byTxID[r.TransactionID] = r
}

// GetByTxID retrieves a receipt by transaction ID.
func (s *Store) GetByTxID(txID string) *model.ComplianceReceipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTxID[txID]
}

// List returns all receipts in insertion order.
func (s *Store) List() []*model.ComplianceReceipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.ComplianceReceipt, len(s.receipts))
	copy(out, s.receipts)
	return out
}
