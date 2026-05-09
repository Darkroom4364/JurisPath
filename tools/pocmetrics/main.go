package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/jurispath/jurispath/internal/pathcheck"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/security"
	"github.com/jurispath/jurispath/pkg/model"
)

type metrics struct {
	PathCheckSamples        int    `json:"path_check_samples"`
	PathCheckP50Ns          int64  `json:"path_check_p50_ns"`
	PathCheckP95Ns          int64  `json:"path_check_p95_ns"`
	ReceiptSizeBytes        int    `json:"receipt_size_bytes"`
	ChainLength             int    `json:"chain_length"`
	ChainVerifyNs           int64  `json:"chain_verify_ns"`
	MissingProofFailure     string `json:"missing_proof_failure"`
	ReceiptStoreFailure     string `json:"receipt_store_failure"`
	EvidenceClass           string `json:"evidence_class"`
	ProofStatus             string `json:"proof_status"`
	ChainVerifyReceiptCount int    `json:"chain_verify_receipt_count"`
}

type failingProofProvider struct {
	err error
}

func (p failingProofProvider) BuildProof(model.ASHop) (model.ISDProof, error) {
	return model.ISDProof{}, p.err
}

type failingStore struct {
	err error
}

func (s failingStore) Append(*model.ComplianceReceipt) error {
	return s.err
}

func (s failingStore) GetByTxID(string) (*model.ComplianceReceipt, error) {
	return nil, nil
}

func (s failingStore) GetByID(string) (*model.ComplianceReceipt, error) {
	return nil, nil
}

func (s failingStore) List() ([]*model.ComplianceReceipt, error) {
	return nil, nil
}

func (s failingStore) Count() (int, error) {
	return 0, nil
}

func (s failingStore) Last() (*model.ComplianceReceipt, error) {
	return nil, nil
}

func (s failingStore) ListRange(uint64, uint64) ([]*model.ComplianceReceipt, error) {
	return nil, nil
}

func main() {
	samples := flag.Int("samples", 1000, "path-check samples")
	chainLength := flag.Int("chain-length", 1000, "receipts to issue and verify")
	jsonOutput := flag.Bool("json", false, "print metrics as JSON")
	flag.Parse()

	if *samples <= 0 {
		fatalf("samples must be positive")
	}
	if *chainLength <= 0 {
		fatalf("chain-length must be positive")
	}

	result, err := collect(*samples, *chainLength)
	if err != nil {
		fatalf("%v", err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fatalf("encode metrics: %v", err)
		}
		return
	}

	fmt.Println("JurisPath PoC metrics")
	fmt.Printf("  path_check_samples: %d\n", result.PathCheckSamples)
	fmt.Printf("  path_check_p50:     %s\n", time.Duration(result.PathCheckP50Ns))
	fmt.Printf("  path_check_p95:     %s\n", time.Duration(result.PathCheckP95Ns))
	fmt.Printf("  receipt_size:       %d bytes\n", result.ReceiptSizeBytes)
	fmt.Printf("  evidence/proof:     %s / %s\n", result.EvidenceClass, result.ProofStatus)
	fmt.Printf("  chain_length:       %d receipts\n", result.ChainLength)
	fmt.Printf("  chain_verify_time:  %s\n", time.Duration(result.ChainVerifyNs))
	fmt.Printf("  missing_proof:      %s\n", result.MissingProofFailure)
	fmt.Printf("  receipt_store:      %s\n", result.ReceiptStoreFailure)
}

func collect(samples, chainLength int) (metrics, error) {
	path, err := demoPath()
	if err != nil {
		return metrics{}, err
	}
	corridorPolicy := &policy.Policy{
		ID:          "chf-eur-settlement-v1",
		Name:        "CHF-EUR Cross-Border Settlement",
		Version:     1,
		AllowedISDs: []uint16{1, 2},
		Mode:        policy.ModeStrict,
	}

	checker := pathcheck.NewChecker(corridorPolicy)
	durations := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		check, err := checker.Check(path)
		durations[i] = time.Since(start)
		if err != nil {
			return metrics{}, fmt.Errorf("path check: %w", err)
		}
		if !check.Compliant {
			return metrics{}, fmt.Errorf("demo path should be compliant: %s", check.ViolatedClause)
		}
	}
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	receiptSize, err := signedReceiptSize(corridorPolicy.ID, path)
	if err != nil {
		return metrics{}, err
	}
	verifiedReceipts, chainVerifyDuration, err := verifyChain(corridorPolicy.ID, path, chainLength)
	if err != nil {
		return metrics{}, err
	}

	missingProof := measureMissingProofFailure(corridorPolicy.ID, path)
	storeFailure := measureReceiptStoreFailure(corridorPolicy.ID, path)

	return metrics{
		PathCheckSamples:        samples,
		PathCheckP50Ns:          percentile(durations, 0.50).Nanoseconds(),
		PathCheckP95Ns:          percentile(durations, 0.95).Nanoseconds(),
		ReceiptSizeBytes:        receiptSize,
		ChainLength:             chainLength,
		ChainVerifyNs:           chainVerifyDuration.Nanoseconds(),
		MissingProofFailure:     missingProof,
		ReceiptStoreFailure:     storeFailure,
		EvidenceClass:           path.EvidenceClass,
		ProofStatus:             path.ProofStatus,
		ChainVerifyReceiptCount: verifiedReceipts,
	}, nil
}

func demoPath() (*model.SCIONPath, error) {
	raw, err := scion.NewMockPath([]model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
		{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"},
	})
	if err != nil {
		return nil, fmt.Errorf("build raw demo path: %w", err)
	}
	path, err := scion.BuildSCIONPath(&scion.MockPathExtractor{}, raw)
	if err != nil {
		return nil, fmt.Errorf("extract demo path: %w", err)
	}
	return path, nil
}

func signedReceiptSize(policyID string, path *model.SCIONPath) (int, error) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		return 0, fmt.Errorf("create receipt generator: %w", err)
	}
	rcpt, err := gen.Issue("tx-metrics-size", policyID, path)
	if err != nil {
		return 0, fmt.Errorf("issue receipt: %w", err)
	}
	data, err := json.Marshal(rcpt)
	if err != nil {
		return 0, fmt.Errorf("marshal receipt: %w", err)
	}
	return len(data), nil
}

func verifyChain(policyID string, path *model.SCIONPath, chainLength int) (int, time.Duration, error) {
	gen, err := receipt.NewGenerator()
	if err != nil {
		return 0, 0, fmt.Errorf("create chain generator: %w", err)
	}
	store := receipt.NewMemoryStore()
	for i := 0; i < chainLength; i++ {
		txID := fmt.Sprintf("tx-metrics-chain-%06d", i+1)
		if _, err := gen.IssueAndAppend(store, txID, policyID, path); err != nil {
			return 0, 0, fmt.Errorf("issue chain receipt %d: %w", i+1, err)
		}
	}
	receipts, err := store.List()
	if err != nil {
		return 0, 0, fmt.Errorf("list chain receipts: %w", err)
	}
	validator := security.NewReceiptValidator(time.Hour)
	start := time.Now()
	if err := validator.ValidateReceiptChain(receipts); err != nil {
		return 0, 0, fmt.Errorf("validate receipt chain: %w", err)
	}
	return len(receipts), time.Since(start), nil
}

func measureMissingProofFailure(policyID string, path *model.SCIONPath) string {
	gen, err := receipt.NewGenerator()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	gen.WithProofProvider(failingProofProvider{err: errors.New("missing TRC proof material")})
	if _, err := gen.Issue("tx-metrics-missing-proof", policyID, path); err != nil {
		return "fail-closed"
	}
	return "unexpected-success"
}

func measureReceiptStoreFailure(policyID string, path *model.SCIONPath) string {
	gen, err := receipt.NewGenerator()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	_, err = gen.IssueAndAppend(failingStore{err: errors.New("disk full")}, "tx-metrics-store-fail", policyID, path)
	var appendErr *receipt.AppendError
	if errors.As(err, &appendErr) && appendErr.ReceiptID != "" {
		return "fail-closed"
	}
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return "unexpected-success"
}

func percentile(durations []time.Duration, pct float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(len(durations))*pct)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(durations) {
		idx = len(durations) - 1
	}
	return durations[idx]
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
