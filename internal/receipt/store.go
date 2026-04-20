package receipt

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"

	"github.com/jurispath/jurispath/pkg/model"
)

var (
	receiptsBucket     = []byte("receipts")
	receiptsByTxBucket = []byte("receipts_by_tx")
	seqBucket          = []byte("seq")
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
}

// NewMemoryStore creates an empty in-memory receipt store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:   make(map[string]*model.ComplianceReceipt),
		byTxID: make(map[string]*model.ComplianceReceipt),
	}
}

func (s *MemoryStore) Append(r *model.ComplianceReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, r)
	s.byID[r.ID] = r
	s.byTxID[r.TransactionID] = r
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
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("opening bolt db: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(receiptsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(receiptsByTxBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(seqBucket); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("creating buckets: %w", err)
	}
	s := &BoltStore{db: db}
	if err := s.backfillSeqBucket(); err != nil {
		db.Close()
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
		if err := tx.Bucket(receiptsBucket).Put([]byte(r.ID), data); err != nil {
			return err
		}
		if err := tx.Bucket(receiptsByTxBucket).Put([]byte(r.TransactionID), []byte(r.ID)); err != nil {
			return err
		}
		seqKey := make([]byte, 8)
		binary.BigEndian.PutUint64(seqKey, r.SeqNo)
		seq := tx.Bucket(seqBucket)
		if err := seq.Put(seqKey, []byte(r.ID)); err != nil {
			return err
		}
		return nil
	})
}

func (s *BoltStore) GetByID(id string) (*model.ComplianceReceipt, error) {
	var r model.ComplianceReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(receiptsBucket).Get([]byte(id))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &r)
	})
	if err != nil {
		return nil, err
	}
	if r.ID == "" {
		return nil, nil
	}
	return &r, nil
}

func (s *BoltStore) GetByTxID(txID string) (*model.ComplianceReceipt, error) {
	var r model.ComplianceReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		receiptID := tx.Bucket(receiptsByTxBucket).Get([]byte(txID))
		if receiptID == nil {
			return nil
		}
		data := tx.Bucket(receiptsBucket).Get(receiptID)
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &r)
	})
	if err != nil {
		return nil, err
	}
	if r.ID == "" {
		return nil, nil
	}
	return &r, nil
}

func (s *BoltStore) List() ([]*model.ComplianceReceipt, error) {
	var out []*model.ComplianceReceipt
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(receiptsBucket).ForEach(func(k, v []byte) error {
			var r model.ComplianceReceipt
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, &r)
			return nil
		})
	})
	return out, err
}

func (s *BoltStore) Count() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(receiptsBucket).Stats().KeyN
		return nil
	})
	return count, err
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
