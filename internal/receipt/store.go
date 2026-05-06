package receipt

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"

	"github.com/jurispath/jurispath/internal/boltutil"
	"github.com/jurispath/jurispath/pkg/model"
)

var (
	receiptsBucket     = []byte("receipts")
	receiptsByTxBucket = []byte("receipts_by_tx")
	seqBucket          = []byte("seq")
)

var (
	ErrDuplicateReceiptID     = errors.New("duplicate receipt id")
	ErrDuplicateTransactionID = errors.New("duplicate transaction id")
	ErrDuplicateSequence      = errors.New("duplicate receipt sequence")
)

// Store is the interface for receipt persistence.
type Store interface {
	Append(r *model.ComplianceReceipt) error
	GetByTxID(txID string) (*model.ComplianceReceipt, error)
	GetByID(id string) (*model.ComplianceReceipt, error)
	List() ([]*model.ComplianceReceipt, error)
	Count() (int, error)
	Last() (*model.ComplianceReceipt, error)
	ListRange(fromSeq, toSeq uint64) ([]*model.ComplianceReceipt, error)
}

// MemoryStore is an in-memory receipt store for testing.
type MemoryStore struct {
	mu       sync.RWMutex
	receipts []*model.ComplianceReceipt
	byID     map[string]*model.ComplianceReceipt
	byTxID   map[string]*model.ComplianceReceipt
	bySeq    map[uint64]*model.ComplianceReceipt
}

// NewMemoryStore creates an empty in-memory receipt store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:   make(map[string]*model.ComplianceReceipt),
		byTxID: make(map[string]*model.ComplianceReceipt),
		bySeq:  make(map[uint64]*model.ComplianceReceipt),
	}
}

func (s *MemoryStore) Append(r *model.ComplianceReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[r.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateReceiptID, r.ID)
	}
	if _, ok := s.byTxID[r.TransactionID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateTransactionID, r.TransactionID)
	}
	if _, ok := s.bySeq[r.SeqNo]; ok {
		return fmt.Errorf("%w: %d", ErrDuplicateSequence, r.SeqNo)
	}
	s.receipts = append(s.receipts, r)
	s.byID[r.ID] = r
	s.byTxID[r.TransactionID] = r
	s.bySeq[r.SeqNo] = r
	return nil
}

func (s *MemoryStore) GetByTxID(txID string) (*model.ComplianceReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTxID[txID], nil
}

func (s *MemoryStore) GetByID(id string) (*model.ComplianceReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id], nil
}

func (s *MemoryStore) List() ([]*model.ComplianceReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.ComplianceReceipt, len(s.receipts))
	copy(out, s.receipts)
	return out, nil
}

func (s *MemoryStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receipts), nil
}

func (s *MemoryStore) Last() (*model.ComplianceReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.receipts) == 0 {
		return nil, nil
	}
	return s.receipts[len(s.receipts)-1], nil
}

func (s *MemoryStore) ListRange(fromSeq, toSeq uint64) ([]*model.ComplianceReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*model.ComplianceReceipt
	for _, r := range s.receipts {
		if r.SeqNo >= fromSeq && r.SeqNo <= toSeq {
			results = append(results, r)
		}
	}
	return results, nil
}

// BoltStore is a persistent receipt store backed by BoltDB.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens or creates a BoltDB-backed receipt store.
func NewBoltStore(dbPath string) (*BoltStore, error) {
	db, err := boltutil.OpenAndInit(dbPath, receiptsBucket, receiptsByTxBucket, seqBucket)
	if err != nil {
		return nil, err
	}
	s := &BoltStore{db: db}
	if err := s.backfillSeqBucket(); err != nil {
		db.Close() //nolint:errcheck // cleanup on init failure
		return nil, fmt.Errorf("backfilling seq bucket: %w", err)
	}
	return s, nil
}

func (s *BoltStore) backfillSeqBucket() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		seq := tx.Bucket(seqBucket)
		if seq.Stats().KeyN > 0 {
			return nil // already populated
		}
		receipts := tx.Bucket(receiptsBucket)
		if receipts == nil {
			return nil
		}
		c := receipts.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r model.ComplianceReceipt
			if err := json.Unmarshal(v, &r); err != nil {
				continue
			}
			seqKey := make([]byte, 8)
			binary.BigEndian.PutUint64(seqKey, r.SeqNo)
			if existing := seq.Get(seqKey); existing != nil {
				return fmt.Errorf("%w: %d", ErrDuplicateSequence, r.SeqNo)
			}
			if err := seq.Put(seqKey, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close closes the underlying BoltDB.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

func (s *BoltStore) Append(r *model.ComplianceReceipt) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshaling receipt: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		receipts := tx.Bucket(receiptsBucket)
		byTx := tx.Bucket(receiptsByTxBucket)
		seq := tx.Bucket(seqBucket)

		if existing := receipts.Get([]byte(r.ID)); existing != nil {
			return fmt.Errorf("%w: %s", ErrDuplicateReceiptID, r.ID)
		}
		if existing := byTx.Get([]byte(r.TransactionID)); existing != nil {
			return fmt.Errorf("%w: %s", ErrDuplicateTransactionID, r.TransactionID)
		}
		seqKey := make([]byte, 8)
		binary.BigEndian.PutUint64(seqKey, r.SeqNo)
		if existing := seq.Get(seqKey); existing != nil {
			return fmt.Errorf("%w: %d", ErrDuplicateSequence, r.SeqNo)
		}

		if err := receipts.Put([]byte(r.ID), data); err != nil {
			return err
		}
		if err := byTx.Put([]byte(r.TransactionID), []byte(r.ID)); err != nil {
			return err
		}
		if err := seq.Put(seqKey, []byte(r.ID)); err != nil {
			return err
		}
		return nil
	})
}

func (s *BoltStore) GetByID(id string) (*model.ComplianceReceipt, error) {
	return boltutil.GetByKey[model.ComplianceReceipt](s.db, receiptsBucket, id)
}

func (s *BoltStore) GetByTxID(txID string) (*model.ComplianceReceipt, error) {
	return boltutil.GetViaIndex[model.ComplianceReceipt](s.db, receiptsByTxBucket, receiptsBucket, txID)
}

func (s *BoltStore) List() ([]*model.ComplianceReceipt, error) {
	return boltutil.ListAll[model.ComplianceReceipt](s.db, receiptsBucket)
}

func (s *BoltStore) Count() (int, error) {
	return boltutil.CountKeys(s.db, receiptsBucket)
}

func (s *BoltStore) Last() (*model.ComplianceReceipt, error) {
	var receipt *model.ComplianceReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		seq := tx.Bucket(seqBucket)
		c := seq.Cursor()
		_, idBytes := c.Last()
		if idBytes == nil {
			return nil // empty
		}
		receipts := tx.Bucket(receiptsBucket)
		data := receipts.Get(idBytes)
		if data == nil {
			return nil
		}
		var r model.ComplianceReceipt
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		receipt = &r
		return nil
	})
	return receipt, err
}

func (s *BoltStore) ListRange(fromSeq, toSeq uint64) ([]*model.ComplianceReceipt, error) {
	var results []*model.ComplianceReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		seq := tx.Bucket(seqBucket)
		receipts := tx.Bucket(receiptsBucket)

		startKey := make([]byte, 8)
		binary.BigEndian.PutUint64(startKey, fromSeq)

		c := seq.Cursor()
		for k, idBytes := c.Seek(startKey); k != nil; k, idBytes = c.Next() {
			seqNo := binary.BigEndian.Uint64(k)
			if seqNo > toSeq {
				break
			}
			data := receipts.Get(idBytes)
			if data == nil {
				continue
			}
			var r model.ComplianceReceipt
			if err := json.Unmarshal(data, &r); err != nil {
				return err
			}
			results = append(results, &r)
		}
		return nil
	})
	return results, err
}
