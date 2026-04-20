package receipt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurispath/jurispath/pkg/model"
)

func TestKeyFile_CreateAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oracle.key")

	gen1, err := NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	gen2, err := NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if !bytes.Equal(gen1.PublicKey(), gen2.PublicKey()) {
		t.Error("public keys should be equal after reload")
	}
}

func TestKeyFile_CorruptedMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oracle.key")
	data := make([]byte, 36)
	copy(data[:4], []byte("BAAD"))
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}

	_, err := NewGeneratorFromFile(path)
	if err == nil || !contains(err.Error(), "bad magic") {
		t.Fatalf("expected bad magic error, got: %v", err)
	}
}

func TestKeyFile_TruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oracle.key")
	data := make([]byte, 20)
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}

	_, err := NewGeneratorFromFile(path)
	if err == nil || !contains(err.Error(), "expected 36 bytes") {
		t.Fatalf("expected size error, got: %v", err)
	}
}

func TestKeyFile_ReceiptsVerifyAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oracle.key")

	gen1, err := NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	p := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "fp1",
	}
	rcpt, err := gen1.Issue("tx-100", "pol-1", p)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}

	// Reload
	_, err = NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("reloading generator: %v", err)
	}

	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if !valid {
		t.Error("receipt should verify after key reload")
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}


func TestGenerator_IssueAndVerify(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
			{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		},
		Fingerprint: "abc123",
	}

	rcpt, err := gen.Issue("tx-001", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}

	if rcpt.TransactionID != "tx-001" {
		t.Errorf("expected tx-001, got %s", rcpt.TransactionID)
	}
	if rcpt.SeqNo != 1 {
		t.Errorf("expected seq 1, got %d", rcpt.SeqNo)
	}
	if len(rcpt.Signature) == 0 {
		t.Error("signature should not be empty")
	}

	// Verify signature
	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying receipt: %v", err)
	}
	if !valid {
		t.Error("receipt signature should be valid")
	}

	// Tamper and verify again
	rcpt.TransactionID = "tx-tampered"
	valid, _ = Verify(rcpt)
	if valid {
		t.Error("tampered receipt should not verify")
	}
}

func TestGenerator_SequenceNumbers(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	path := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "test",
	}

	r1, _ := gen.Issue("tx-1", "p1", path)
	r2, _ := gen.Issue("tx-2", "p1", path)

	if r2.SeqNo <= r1.SeqNo {
		t.Errorf("sequence numbers must be monotonically increasing: %d <= %d", r2.SeqNo, r1.SeqNo)
	}
}
