package receipt_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/pkg/model"
)

func makeReceipt(id, txID string) *model.ComplianceReceipt {
	return &model.ComplianceReceipt{
		ID:            id,
		TransactionID: txID,
		PolicyID:      "policy-1",
		Path: model.SCIONPath{
			Fingerprint: "fp-" + id,
		},
		SeqNo:     1,
		Timestamp: time.Now().UTC(),
	}
}

func TestBoltStore_AppendAndGetByID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "receipts.db")
	store, err := receipt.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	r := makeReceipt("r1", "tx1")
	if err := store.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByID("r1")
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

func TestBoltStore_GetByTxID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "receipts.db")
	store, err := receipt.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	r := makeReceipt("r1", "tx1")
	if err := store.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByTxID("tx1")
	if err != nil {
		t.Fatalf("GetByTxID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByTxID returned nil")
	}
	if got.ID != "r1" {
		t.Errorf("got id %q, want r1", got.ID)
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

func TestBoltStore_ListAndCount(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "receipts.db")
	store, err := receipt.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	for i := 0; i < 5; i++ {
		r := makeReceipt("r"+string(rune('A'+i)), "tx"+string(rune('A'+i)))
		if err := store.Append(r); err != nil {
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

func TestBoltStore_Persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "receipts.db")

	// Write data
	store, err := receipt.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	r := makeReceipt("r1", "tx1")
	if err := store.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_ = store.Close()

	// Reopen and verify
	store2, err := receipt.NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("NewBoltStore (reopen): %v", err)
	}
	defer func() { _ = store2.Close() }()

	got, err := store2.GetByID("r1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("receipt not persisted across close/reopen")
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

func TestMemoryStore_Interface(t *testing.T) {
	var store receipt.Store = receipt.NewMemoryStore()

	r := makeReceipt("r1", "tx1")
	if err := store.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.GetByID("r1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil || got.TransactionID != "tx1" {
		t.Errorf("unexpected result: %+v", got)
	}
}
