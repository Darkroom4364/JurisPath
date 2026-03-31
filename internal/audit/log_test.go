package audit_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jurispath/jurispath/internal/audit"
)

func TestAuditLog_AppendAndList(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	al, err := audit.NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer al.Close()

	for i := 0; i < 10; i++ {
		entry := audit.AuditEntry{
			Timestamp: time.Now().UTC(),
			EventType: "check",
			Details:   json.RawMessage(`{"index":` + string(rune('0'+i)) + `}`),
		}
		if err := al.Append(entry); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	count, err := al.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 10 {
		t.Errorf("Count returned %d, want 10", count)
	}

	// Paginated retrieval
	entries, err := al.List(0, 5)
	if err != nil {
		t.Fatalf("List(0,5): %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("List(0,5) returned %d entries, want 5", len(entries))
	}

	entries2, err := al.List(5, 5)
	if err != nil {
		t.Fatalf("List(5,5): %v", err)
	}
	if len(entries2) != 5 {
		t.Errorf("List(5,5) returned %d entries, want 5", len(entries2))
	}

	// Beyond range
	entries3, err := al.List(10, 5)
	if err != nil {
		t.Fatalf("List(10,5): %v", err)
	}
	if len(entries3) != 0 {
		t.Errorf("List(10,5) returned %d entries, want 0", len(entries3))
	}
}

func TestAuditLog_Persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	al, err := audit.NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	entry := audit.AuditEntry{
		Timestamp: time.Now().UTC(),
		EventType: "receipt",
		Details:   json.RawMessage(`{"id":"r1"}`),
	}
	if err := al.Append(entry); err != nil {
		t.Fatalf("Append: %v", err)
	}
	al.Close()

	al2, err := audit.NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog (reopen): %v", err)
	}
	defer al2.Close()

	count, err := al2.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Errorf("Count returned %d, want 1", count)
	}

	entries, err := al2.List(0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1", len(entries))
	}
	if entries[0].EventType != "receipt" {
		t.Errorf("got event type %q, want receipt", entries[0].EventType)
	}
}

func TestAuditLog_EventTypes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	al, err := audit.NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer al.Close()

	types := []string{"check", "receipt", "violation", "settle"}
	for _, et := range types {
		entry := audit.AuditEntry{
			Timestamp: time.Now().UTC(),
			EventType: et,
			Details:   json.RawMessage(`{}`),
		}
		if err := al.Append(entry); err != nil {
			t.Fatalf("Append %s: %v", et, err)
		}
	}

	entries, err := al.List(0, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("got %d entries, want 4", len(entries))
	}
}
