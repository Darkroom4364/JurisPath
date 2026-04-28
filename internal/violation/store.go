package violation

import (
	"encoding/json"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"

	"github.com/jurispath/jurispath/internal/boltutil"
	"github.com/jurispath/jurispath/pkg/model"
)

var (
	violationsBucket     = []byte("violations")
	violationsByTxBucket = []byte("violations_by_tx")
)

// ViolationStore is the interface for violation persistence.
type ViolationStore interface {
	Append(v *model.Violation) error
	GetByID(id string) (*model.Violation, error)
	GetByTxID(txID string) (*model.Violation, error)
	List() ([]*model.Violation, error)
	Count() (int, error)
}

// MemoryViolationStore is an in-memory violation store for testing.
type MemoryViolationStore struct {
	mu         sync.RWMutex
	violations []*model.Violation
	byID       map[string]*model.Violation
	byTxID     map[string]*model.Violation
}

// NewMemoryViolationStore creates an empty in-memory violation store.
func NewMemoryViolationStore() *MemoryViolationStore {
	return &MemoryViolationStore{
		byID:   make(map[string]*model.Violation),
		byTxID: make(map[string]*model.Violation),
	}
}

func (s *MemoryViolationStore) Append(v *model.Violation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.violations = append(s.violations, v)
	s.byID[v.ID] = v
	s.byTxID[v.TransactionID] = v
	return nil
}

func (s *MemoryViolationStore) GetByID(id string) (*model.Violation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id], nil
}

func (s *MemoryViolationStore) GetByTxID(txID string) (*model.Violation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTxID[txID], nil
}

func (s *MemoryViolationStore) List() ([]*model.Violation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Violation, len(s.violations))
	copy(out, s.violations)
	return out, nil
}

func (s *MemoryViolationStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.violations), nil
}

// BoltViolationStore is a persistent violation store backed by BoltDB.
type BoltViolationStore struct {
	db *bolt.DB
}

// NewBoltViolationStore opens or creates a BoltDB-backed violation store.
func NewBoltViolationStore(dbPath string) (*BoltViolationStore, error) {
	db, err := boltutil.OpenAndInit(dbPath, violationsBucket, violationsByTxBucket)
	if err != nil {
		return nil, err
	}
	return &BoltViolationStore{db: db}, nil
}

// Close closes the underlying BoltDB.
func (s *BoltViolationStore) Close() error {
	return s.db.Close()
}

func (s *BoltViolationStore) Append(v *model.Violation) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling violation: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(violationsBucket).Put([]byte(v.ID), data); err != nil {
			return err
		}
		return tx.Bucket(violationsByTxBucket).Put([]byte(v.TransactionID), []byte(v.ID))
	})
}

func (s *BoltViolationStore) GetByID(id string) (*model.Violation, error) {
	return boltutil.GetByKey[model.Violation](s.db, violationsBucket, id)
}

func (s *BoltViolationStore) GetByTxID(txID string) (*model.Violation, error) {
	return boltutil.GetViaIndex[model.Violation](s.db, violationsByTxBucket, violationsBucket, txID)
}

func (s *BoltViolationStore) List() ([]*model.Violation, error) {
	return boltutil.ListAll[model.Violation](s.db, violationsBucket)
}

func (s *BoltViolationStore) Count() (int, error) {
	return boltutil.CountKeys(s.db, violationsBucket)
}
