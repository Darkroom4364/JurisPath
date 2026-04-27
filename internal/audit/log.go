package audit

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var auditBucket = []byte("audit")

// AuditEntry represents a single entry in the append-only audit log.
type AuditEntry struct {
	Timestamp time.Time        `json:"timestamp"`
	EventType string           `json:"event_type"` // "check", "receipt", "violation", "settle"
	Details   json.RawMessage  `json:"details"`
}

// AuditLog is an append-only audit trail backed by BoltDB.
type AuditLog struct {
	db *bolt.DB
}

// NewAuditLog opens or creates a BoltDB-backed audit log.
func NewAuditLog(dbPath string) (*AuditLog, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("opening audit db: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(auditBucket)
		return err
	})
	if err != nil {
		db.Close() //nolint:errcheck // cleanup on init failure
		return nil, fmt.Errorf("creating audit bucket: %w", err)
	}
	return &AuditLog{db: db}, nil
}

// Close closes the underlying BoltDB.
func (a *AuditLog) Close() error {
	return a.db.Close()
}

// Append adds an entry to the audit log using an auto-incrementing sequence key.
func (a *AuditLog) Append(entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling audit entry: %w", err)
	}
	return a.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, seq)
		return b.Put(key, data)
	})
}

// List returns audit entries with pagination (offset and limit).
func (a *AuditLog) List(offset, limit int) ([]AuditEntry, error) {
	var entries []AuditEntry
	err := a.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(auditBucket).Cursor()
		i := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if i < offset {
				i++
				continue
			}
			if len(entries) >= limit {
				break
			}
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			entries = append(entries, entry)
			i++
		}
		return nil
	})
	return entries, err
}

// Count returns the total number of audit entries.
func (a *AuditLog) Count() (int, error) {
	var count int
	err := a.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(auditBucket).Stats().KeyN
		return nil
	})
	return count, err
}
