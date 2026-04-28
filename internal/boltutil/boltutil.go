package boltutil

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// OpenAndInit opens a BoltDB file and creates the given buckets.
func OpenAndInit(dbPath string, buckets ...[]byte) (*bolt.DB, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("opening bolt db: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close() //nolint:errcheck // cleanup on init failure
		return nil, fmt.Errorf("creating buckets: %w", err)
	}
	return db, nil
}

// GetByKey retrieves and unmarshals an entity by primary key from a bucket.
// Returns (nil, nil) if not found.
func GetByKey[T any](db *bolt.DB, bucket []byte, key string) (*T, error) {
	var result T
	var found bool
	err := db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucket).Get([]byte(key))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &result)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &result, nil
}

// GetViaIndex looks up a primary key through an index bucket, then retrieves
// the entity from the data bucket. Returns (nil, nil) if not found.
func GetViaIndex[T any](db *bolt.DB, indexBucket, dataBucket []byte, key string) (*T, error) {
	var result T
	var found bool
	err := db.View(func(tx *bolt.Tx) error {
		pk := tx.Bucket(indexBucket).Get([]byte(key))
		if pk == nil {
			return nil
		}
		data := tx.Bucket(dataBucket).Get(pk)
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &result)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &result, nil
}

// ListAll iterates a bucket and unmarshals every value into a slice.
func ListAll[T any](db *bolt.DB, bucket []byte) ([]*T, error) {
	var out []*T
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(_, v []byte) error {
			var item T
			if err := json.Unmarshal(v, &item); err != nil {
				return err
			}
			out = append(out, &item)
			return nil
		})
	})
	return out, err
}

// CountKeys returns the number of keys in a bucket.
func CountKeys(db *bolt.DB, bucket []byte) (int, error) {
	var count int
	err := db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucket).Stats().KeyN
		return nil
	})
	return count, err
}
