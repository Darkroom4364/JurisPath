package violation_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jurispath/jurispath/internal/violation"
	"github.com/jurispath/jurispath/pkg/model"
)

func makeViolation(id, txID string) *model.Violation {
	return &model.Violation{
		ID:             id,
		TransactionID:  txID,
		PolicyID:       "policy-1",
		ViolatedClause: "data_sovereignty",
		Severity:       "high",
		Path: model.SCIONPath{
			Fingerprint: "fp-" + id,
		},
		Timestamp: time.Now().UTC(),
	}
}

func TestBoltViolationStore_AppendAndGetByID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "violations.db")
	store, err := violation.NewBoltViolationStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltViolationStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	v := makeViolation("v1", "tx1")
	if err := store.Append(v); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByID("v1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID returned nil")
	}
	if got.TransactionID != "tx1" {
		t.Errorf("got tx %q, want tx1", got.TransactionID)
	}
}

func TestBoltViolationStore_GetByTxID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "violations.db")
	store, err := violation.NewBoltViolationStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltViolationStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	v := makeViolation("v1", "tx1")
	if err := store.Append(v); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByTxID("tx1")
	if err != nil {
		t.Fatalf("GetByTxID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByTxID returned nil")
	}
	if got.ID != "v1" {
		t.Errorf("got id %q, want v1", got.ID)
	}

	// Non-existent tx
	got, err = store.GetByTxID("no-such-tx")
	if err != nil {
		t.Fatalf("GetByTxID: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestBoltViolationStore_ListAndCount(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "violations.db")
	store, err := violation.NewBoltViolationStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltViolationStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	for i := 0; i < 5; i++ {
		v := makeViolation("v"+string(rune('A'+i)), "tx"+string(rune('A'+i)))
		if err := store.Append(v); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 5 {
		t.Errorf("List returned %d items, want 5", len(list))
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 5 {
		t.Errorf("Count returned %d, want 5", count)
	}
}

func TestBoltViolationStore_Persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "violations.db")

	// Write data
	store, err := violation.NewBoltViolationStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltViolationStore: %v", err)
	}
	v := makeViolation("v1", "tx1")
	if err := store.Append(v); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_ = store.Close()

	// Reopen and verify
	store2, err := violation.NewBoltViolationStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltViolationStore (reopen): %v", err)
	}
	defer func() { _ = store2.Close() }()

	got, err := store2.GetByID("v1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("violation not persisted across close/reopen")
	}
	if got.TransactionID != "tx1" {
		t.Errorf("got tx %q, want tx1", got.TransactionID)
	}

	got2, err := store2.GetByTxID("tx1")
	if err != nil {
		t.Fatalf("GetByTxID: %v", err)
	}
	if got2 == nil {
		t.Fatal("tx index not persisted across close/reopen")
	}

	count, err := store2.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("Count returned %d, want 1", count)
	}
}

func TestMemoryViolationStore_Interface(t *testing.T) {
	var store violation.ViolationStore = violation.NewMemoryViolationStore()

	v := makeViolation("v1", "tx1")
	if err := store.Append(v); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByID("v1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil || got.TransactionID != "tx1" {
		t.Errorf("unexpected result: %+v", got)
	}
}
