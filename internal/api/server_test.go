package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jurispath/jurispath/internal/audit"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/violation"
	"github.com/jurispath/jurispath/pkg/model"
)

// testEnv bundles everything needed for an integration test.
type testEnv struct {
	server *httptest.Server
	ledger *dlt.Ledger
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	pol := &policy.Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Mode:        "strict",
		AllowedISDs: []uint16{1, 2},
		Version:     1,
	}

	validators := []dlt.ValidatorState{
		{ID: "CH", Address: "1-ff00:0:110,[127.0.0.1]:30100", Balance: map[string]int64{"CHF": 10000}},
		{ID: "EU", Address: "2-ff00:0:210,[127.0.0.1]:30200", Balance: map[string]int64{"CHF": 10000}},
		{ID: "X", Address: "3-ff00:0:310,[127.0.0.1]:30300", Balance: map[string]int64{"CHF": 10000}},
	}

	ledger := dlt.NewLedger(validators)
	consensus := dlt.NewConsensusEngine(ledger, validators)

	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating receipt generator: %v", err)
	}

	rs := receipt.NewMemoryStore()
	vs := violation.NewMemoryViolationStore()
	det := violation.NewDetector(vs)
	ext := &scion.MockPathExtractor{}

	al, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("creating audit log: %v", err)
	}

	srv := NewServer([]*policy.Policy{pol}, gen, ext, ledger, consensus, rs, det, al, t.TempDir())
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)

	return &testEnv{server: ts, ledger: ledger}
}

func compliantPath(t *testing.T) []byte {
	t.Helper()
	hops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
	}
	raw, err := scion.NewMockPath(hops)
	if err != nil {
		t.Fatalf("creating mock path: %v", err)
	}
	return raw
}

func nonCompliantPath(t *testing.T) []byte {
	t.Helper()
	hops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
	}
	raw, err := scion.NewMockPath(hops)
	if err != nil {
		t.Fatalf("creating mock path: %v", err)
	}
	return raw
}

func postSettle(t *testing.T, url string, req SettleRequest) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(url+"/api/settle", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/settle: %v", err)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return resp, result
}

func TestSettleCompliantPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		PolicyID: "test-policy",
		RawPath:  compliantPath(t),
	})

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, result)
	}

	consensus, ok := result["consensus"].(map[string]any)
	if !ok {
		t.Fatal("missing consensus in response")
	}
	if consensus["confirmed"] != true {
		t.Fatalf("expected consensus.confirmed=true, got %v", consensus["confirmed"])
	}

	compliance, ok := result["compliance"].(map[string]any)
	if !ok {
		t.Fatal("missing compliance in response")
	}
	if compliance["compliant"] != true {
		t.Fatalf("expected compliance.compliant=true, got %v", compliance["compliant"])
	}
	if compliance["receipt"] == nil {
		t.Fatal("expected a receipt in compliance response")
	}
}

func TestSettleNonCompliantPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		PolicyID: "test-policy",
		RawPath:  nonCompliantPath(t),
	})

	if resp.StatusCode != 422 {
		t.Fatalf("expected 422, got %d: %v", resp.StatusCode, result)
	}

	compliance, ok := result["compliance"].(map[string]any)
	if !ok {
		t.Fatal("missing compliance in response")
	}
	if compliance["violation"] == nil {
		t.Fatal("expected a violation in compliance response")
	}

	// Verify balances unchanged via GET /api/ledger
	ledgerResp, err := http.Get(env.server.URL + "/api/ledger")
	if err != nil {
		t.Fatalf("GET /api/ledger: %v", err)
	}
	defer ledgerResp.Body.Close()
	var lr LedgerResponse
	json.NewDecoder(ledgerResp.Body).Decode(&lr)

	for _, v := range lr.Validators {
		if v.Balance["CHF"] != 10000 {
			t.Fatalf("expected balance 10000 for %s, got %d", v.ID, v.Balance["CHF"])
		}
	}
}

func TestSettleMissingPolicy(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		RawPath:  compliantPath(t),
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if result["code"] != "POLICY_REQUIRED" {
		t.Fatalf("expected code POLICY_REQUIRED, got %v", result["code"])
	}
}

func TestSettleMissingPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		PolicyID: "test-policy",
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if result["code"] != "PATH_REQUIRED" {
		t.Fatalf("expected code PATH_REQUIRED, got %v", result["code"])
	}
}

func TestSettleCompliancePassConsensusRejects(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   999999,
		Currency: "CHF",
		PolicyID: "test-policy",
		RawPath:  compliantPath(t),
	})

	// The ledger rejects at submit time due to insufficient balance, so we get 400.
	if resp.StatusCode != 400 {
		// If it somehow passed submit, check consensus result
		if resp.StatusCode == 200 {
			consensus, ok := result["consensus"].(map[string]any)
			if !ok {
				t.Fatal("missing consensus in response")
			}
			if consensus["confirmed"] != false {
				t.Fatalf("expected consensus.confirmed=false, got %v", consensus["confirmed"])
			}
			if result["compliance"] != nil {
				compliance := result["compliance"].(map[string]any)
				if compliance["receipt"] != nil {
					t.Fatal("expected no receipt when consensus rejects")
				}
			}
			return
		}
		t.Fatalf("expected 400 or 200 with confirmed=false, got %d: %v", resp.StatusCode, result)
	}
}

func TestSettleUnknownPolicy(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		PolicyID: "nonexistent-policy",
		RawPath:  compliantPath(t),
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if result["code"] != "UNKNOWN_POLICY" {
		t.Fatalf("expected code UNKNOWN_POLICY, got %v", result["code"])
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/verify-chain")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	chainLen := int(result["chain_length"].(float64))
	if chainLen != 0 {
		t.Errorf("expected chain_length 0, got %d", chainLen)
	}
	if result["oracle_public_key"] == nil {
		t.Error("expected oracle_public_key to be set")
	}
}

func TestVerifyChainMaxRange(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/verify-chain?from_seq=1&to_seq=2000")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestVerifyChainAfterSettle(t *testing.T) {
	env := setupTestEnv(t)

	// Settle a compliant transaction
	settleBody, _ := json.Marshal(map[string]any{
		"from":      "CH",
		"to":        "EU",
		"amount":    100,
		"currency":  "CHF",
		"policy_id": "test-policy",
		"raw_path":  compliantPath(t),
	})
	settleResp, err := http.Post(env.server.URL+"/api/settle", "application/json", bytes.NewReader(settleBody))
	if err != nil {
		t.Fatalf("settle failed: %v", err)
	}
	settleResp.Body.Close()
	if settleResp.StatusCode != 200 {
		t.Fatalf("settle expected 200, got %d", settleResp.StatusCode)
	}

	// Now verify the chain
	resp, err := http.Get(env.server.URL + "/api/verify-chain")
	if err != nil {
		t.Fatalf("verify-chain failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	chainLen := int(result["chain_length"].(float64))
	if chainLen != 1 {
		t.Errorf("expected chain_length 1, got %d", chainLen)
	}

	receipts := result["receipts"].([]any)
	if len(receipts) != 1 {
		t.Errorf("expected 1 receipt, got %d", len(receipts))
	}
}

func TestHealthEndpoint(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var health map[string]any
	json.NewDecoder(resp.Body).Decode(&health)

	if health["audit_healthy"] != true {
		t.Errorf("expected audit_healthy=true, got %v", health["audit_healthy"])
	}
}

func postCheck(t *testing.T, url string, req CheckRequest) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(url+"/api/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/check: %v", err)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return resp, result
}

func TestCheckCompliantPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-compliant-1",
		PolicyID:      "test-policy",
		RawPath:       compliantPath(t),
	})

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, result)
	}
	if result["compliant"] != true {
		t.Fatalf("expected compliant=true, got %v", result["compliant"])
	}
	if result["receipt"] == nil {
		t.Fatal("expected a receipt in response")
	}
}

func TestCheckNonCompliantPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-noncompliant-1",
		PolicyID:      "test-policy",
		RawPath:       nonCompliantPath(t),
	})

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, result)
	}
	if result["compliant"] != false {
		t.Fatalf("expected compliant=false, got %v", result["compliant"])
	}
	if result["violation"] == nil {
		t.Fatal("expected a violation in response")
	}
}

func TestCheckUnknownPolicy(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-unknown-1",
		PolicyID:      "nonexistent-policy",
		RawPath:       compliantPath(t),
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if result["code"] != "UNKNOWN_POLICY" {
		t.Fatalf("expected code UNKNOWN_POLICY, got %v", result["code"])
	}
}

func TestCheckInvalidBody(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Post(env.server.URL+"/api/check", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("POST /api/check: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if result["code"] != "INVALID_REQUEST" {
		t.Fatalf("expected code INVALID_REQUEST, got %v", result["code"])
	}
}

func TestCheckMissingRawPath(t *testing.T) {
	env := setupTestEnv(t)

	resp, result := postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-nopath-1",
		PolicyID:      "test-policy",
		RawPath:       nil,
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d: %v", resp.StatusCode, result)
	}
}
