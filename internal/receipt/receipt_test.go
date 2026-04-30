package receipt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jurispath/jurispath/pkg/model"
)

type testProofProvider struct {
	err error
}

func (p testProofProvider) BuildProof(hop model.ASHop) (model.ISDProof, error) {
	if p.err != nil {
		return model.ISDProof{}, p.err
	}
	return model.ISDProof{
		IA:                 hop.IA,
		ISD:                hop.ISD,
		TRCSerial:          uint64(1000 + hop.ISD),
		CertChain:          []byte("test-cert-chain-" + hop.IA),
		VerificationStatus: "verified",
		ProofSource:        "test-trc",
	}, nil
}

type legacyProofProvider struct{}

func (legacyProofProvider) BuildProof(hop model.ASHop) (model.ISDProof, error) {
	return model.ISDProof{IA: hop.IA, ISD: hop.ISD}, nil
}

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

func TestKeyFile_RotatePreservesSequenceAndHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oracle.key")

	gen, err := NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}
	oldPublicKey := append([]byte(nil), gen.PublicKey()...)

	p := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "fp1",
	}
	r1, err := gen.Issue("tx-before-rotate", "pol-1", p)
	if err != nil {
		t.Fatalf("issuing first receipt: %v", err)
	}

	archivePath, err := gen.RotateKeyFile(path)
	if err != nil {
		t.Fatalf("rotating key: %v", err)
	}
	if archivePath == "" {
		t.Fatal("expected archived key path")
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("expected archived key to exist: %v", err)
	}
	if bytes.Equal(oldPublicKey, gen.PublicKey()) {
		t.Fatal("expected rotated public key to differ")
	}

	r2, err := gen.Issue("tx-after-rotate", "pol-1", p)
	if err != nil {
		t.Fatalf("issuing second receipt: %v", err)
	}
	if r2.SeqNo != r1.SeqNo+1 {
		t.Fatalf("expected rotated receipt seq %d, got %d", r1.SeqNo+1, r2.SeqNo)
	}
	expectedHash := sha256.Sum256(r1.Signature)
	if !bytes.Equal(r2.PreviousHash, expectedHash[:]) {
		t.Fatalf("rotated receipt previous hash = %x, want %x", r2.PreviousHash, expectedHash[:])
	}

	for _, r := range []*model.ComplianceReceipt{r1, r2} {
		valid, err := Verify(r)
		if err != nil {
			t.Fatalf("verifying receipt: %v", err)
		}
		if !valid {
			t.Fatalf("receipt %s should verify", r.ID)
		}
	}

	reloaded, err := NewGeneratorFromFile(path)
	if err != nil {
		t.Fatalf("reloading rotated key: %v", err)
	}
	if !bytes.Equal(reloaded.PublicKey(), gen.PublicKey()) {
		t.Fatal("reloaded generator should use rotated key")
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

func TestGenerator_IssueUsesConfiguredProofProvider(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}
	gen.WithProofProvider(testProofProvider{})

	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		},
		Fingerprint: "abc123",
	}
	rcpt, err := gen.Issue("tx-proof", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}
	if len(rcpt.ISDProofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(rcpt.ISDProofs))
	}
	proof := rcpt.ISDProofs[0]
	if proof.TRCSerial != 1001 {
		t.Fatalf("TRCSerial = %d, want 1001", proof.TRCSerial)
	}
	if proof.VerificationStatus != "verified" {
		t.Fatalf("VerificationStatus = %q, want verified", proof.VerificationStatus)
	}
	if proof.ProofSource != "test-trc" {
		t.Fatalf("ProofSource = %q, want test-trc", proof.ProofSource)
	}
	if len(proof.CertChain) == 0 {
		t.Fatal("expected cert chain proof material")
	}
	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying receipt: %v", err)
	}
	if !valid {
		t.Fatal("receipt with configured proof should verify")
	}
}

func TestGenerator_LegacyProofMetadataOmittedFromSigningPayload(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}
	gen.WithProofProvider(legacyProofProvider{})

	path := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "legacy-proof",
	}
	rcpt, err := gen.Issue("tx-legacy-proof", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}
	payload, err := marshalForSigning(rcpt)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	if bytes.Contains(payload, []byte("verification_status")) {
		t.Fatal("empty verification_status should be omitted from signing payload")
	}
	if bytes.Contains(payload, []byte("proof_source")) {
		t.Fatal("empty proof_source should be omitted from signing payload")
	}
}

func TestGenerator_IssueFailsWhenProofProviderFails(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}
	gen.WithProofProvider(testProofProvider{err: errors.New("missing TRC")})

	path := &model.SCIONPath{
		Hops:        []model.ASHop{{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}},
		Fingerprint: "abc123",
	}
	_, err = gen.Issue("tx-proof-fail", "policy-v1", path)
	if err == nil {
		t.Fatal("expected proof provider error")
	}
	if !strings.Contains(err.Error(), "building ISD proof") {
		t.Fatalf("expected ISD proof error, got %v", err)
	}

	gen.WithProofProvider(testProofProvider{})
	rcpt, err := gen.Issue("tx-proof-ok", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing after proof failure: %v", err)
	}
	if rcpt.SeqNo != 1 {
		t.Fatalf("failed proof issuance should not consume sequence number, got seq %d", rcpt.SeqNo)
	}
}

func TestGenerator_IssueWithRawPath(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	// Simulate a receipt with raw SCION dataplane bytes.
	path := &model.SCIONPath{
		Raw: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110", HopMAC: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
		},
		Fingerprint: "raw-fp",
	}

	rcpt, err := gen.Issue("tx-raw", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}

	// Verify signature covers the raw path.
	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying receipt: %v", err)
	}
	if !valid {
		t.Error("receipt with raw path should verify")
	}

	// Tampering with raw path bytes should break verification.
	rcpt.Path.Raw[0] = 0xFF
	valid, _ = Verify(rcpt)
	if valid {
		t.Error("receipt with tampered raw path should NOT verify")
	}
}

func TestGenerator_MockModeBackwardCompat(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("creating generator: %v", err)
	}

	// Receipt without raw path (mock mode) — should still sign and verify.
	path := &model.SCIONPath{
		Hops: []model.ASHop{
			{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		},
		Fingerprint: "mock-fp",
	}

	rcpt, err := gen.Issue("tx-mock", "policy-v1", path)
	if err != nil {
		t.Fatalf("issuing receipt: %v", err)
	}

	valid, err := Verify(rcpt)
	if err != nil {
		t.Fatalf("verifying receipt: %v", err)
	}
	if !valid {
		t.Error("mock-mode receipt should verify")
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
