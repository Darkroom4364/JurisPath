package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jurispath/jurispath/internal/audit"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/security"
	"github.com/jurispath/jurispath/internal/violation"
	"github.com/jurispath/jurispath/pkg/model"
)

// testEnv bundles everything needed for an integration test.
type testEnv struct {
	server *httptest.Server
	api    *Server
	ledger *dlt.Ledger
	audit  *audit.AuditLog
}

type failingAppendReceiptStore struct {
	inner receipt.Store
	err   error
}

type rejectingPathExtractor struct{}

func (rejectingPathExtractor) ExtractHops([]byte) ([]model.ASHop, error) {
	return nil, errors.New("SCION path extraction unavailable")
}

func (s *failingAppendReceiptStore) Append(_ *model.ComplianceReceipt) error {
	return s.err
}

func (s *failingAppendReceiptStore) GetByTxID(txID string) (*model.ComplianceReceipt, error) {
	return s.inner.GetByTxID(txID)
}

func (s *failingAppendReceiptStore) GetByID(id string) (*model.ComplianceReceipt, error) {
	return s.inner.GetByID(id)
}

func (s *failingAppendReceiptStore) List() ([]*model.ComplianceReceipt, error) {
	return s.inner.List()
}

func (s *failingAppendReceiptStore) Count() (int, error) {
	return s.inner.Count()
}

func (s *failingAppendReceiptStore) Last() (*model.ComplianceReceipt, error) {
	return s.inner.Last()
}

func (s *failingAppendReceiptStore) ListRange(fromSeq, toSeq uint64) ([]*model.ComplianceReceipt, error) {
	return s.inner.ListRange(fromSeq, toSeq)
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return setupTestEnvWithReceiptStore(t, receipt.NewMemoryStore())
}

func setupTestEnvWithReceiptStore(t *testing.T, rs receipt.Store) *testEnv {
	t.Helper()
	return setupTestEnvWithReceiptStoreAndExtractor(t, rs, &scion.MockPathExtractor{})
}

func setupTestEnvWithExtractor(t *testing.T, ext scion.PathExtractor) *testEnv {
	t.Helper()
	return setupTestEnvWithReceiptStoreAndExtractor(t, receipt.NewMemoryStore(), ext)
}

func setupTestEnvWithReceiptStoreAndExtractor(t *testing.T, rs receipt.Store, ext scion.PathExtractor) *testEnv {
	t.Helper()
	return setupTestEnvWithReceiptStoreExtractorAndOptions(t, rs, ext)
}

func setupTestEnvWithAuthToken(t *testing.T, token string) *testEnv {
	t.Helper()
	return setupTestEnvWithReceiptStoreExtractorAndOptions(t, receipt.NewMemoryStore(), &scion.MockPathExtractor{}, WithBearerToken(token))
}

func setupTestEnvWithReceiptStoreExtractorAndOptions(t *testing.T, rs receipt.Store, ext scion.PathExtractor, opts ...ServerOption) *testEnv {
	t.Helper()
	return setupTestEnvWithGeneratorReceiptStoreExtractorAndOptions(t, mustGenerator(t), rs, ext, opts...)
}

func mustGenerator(t *testing.T) *receipt.Generator {
	t.Helper()
	gen, err := receipt.NewGenerator()
	if err != nil {
		t.Fatalf("creating receipt generator: %v", err)
	}
	return gen
}

func setupTestEnvWithGeneratorReceiptStoreExtractorAndOptions(t *testing.T, gen *receipt.Generator, rs receipt.Store, ext scion.PathExtractor, opts ...ServerOption) *testEnv {
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

	vs := violation.NewMemoryViolationStore()
	det := violation.NewDetector(vs)

	al, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("creating audit log: %v", err)
	}

	srv := NewServer([]*policy.Policy{pol}, gen, ext, ledger, consensus, rs, det, al, t.TempDir(), opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		if err := al.Close(); err != nil {
			t.Fatalf("closing audit log: %v", err)
		}
	})

	return &testEnv{server: ts, api: srv, ledger: ledger, audit: al}
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

func TestNewHTTPServer_HardeningDefaults(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	tests := []struct {
		name string
		addr string
	}{
		{name: "standard address", addr: "127.0.0.1:8080"},
		{name: "empty address", addr: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := NewHTTPServer(tc.addr, handler)
			if srv.Addr != tc.addr {
				t.Fatalf("expected addr %q, got %q", tc.addr, srv.Addr)
			}
			if srv.Handler == nil {
				t.Fatal("expected configured handler to be non-nil")
			}
			if srv.ReadHeaderTimeout != defaultReadHeaderTimeout {
				t.Fatalf("expected ReadHeaderTimeout=%s, got %s", defaultReadHeaderTimeout, srv.ReadHeaderTimeout)
			}
			if srv.ReadTimeout != defaultReadTimeout {
				t.Fatalf("expected ReadTimeout=%s, got %s", defaultReadTimeout, srv.ReadTimeout)
			}
			if srv.WriteTimeout != defaultWriteTimeout {
				t.Fatalf("expected WriteTimeout=%s, got %s", defaultWriteTimeout, srv.WriteTimeout)
			}
			if srv.IdleTimeout != defaultIdleTimeout {
				t.Fatalf("expected IdleTimeout=%s, got %s", defaultIdleTimeout, srv.IdleTimeout)
			}
			if srv.MaxHeaderBytes != defaultMaxHeaderBytes {
				t.Fatalf("expected MaxHeaderBytes=%d, got %d", defaultMaxHeaderBytes, srv.MaxHeaderBytes)
			}
		})
	}
}

func TestHandlerSetsContentSecurityPolicy(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, contentSecurityPolicy)
	}
}

func TestBearerAuthProtectsAPIEndpoints(t *testing.T) {
	env := setupTestEnvWithAuthToken(t, "test-token")

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{name: "missing token", want: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "correct token", header: "Bearer test-token", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, env.server.URL+"/api/policies", nil)
			if err != nil {
				t.Fatalf("creating request: %v", err)
			}
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET /api/policies: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, resp.StatusCode)
			}
			if tc.want == http.StatusUnauthorized {
				var result map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if result["code"] != "UNAUTHORIZED" {
					t.Fatalf("expected code UNAUTHORIZED, got %v", result["code"])
				}
				if resp.Header.Get("WWW-Authenticate") == "" {
					t.Fatal("expected WWW-Authenticate header")
				}
			}
		})
	}
}

func TestBearerAuthHealthFollowsAPIRule(t *testing.T) {
	env := setupTestEnvWithAuthToken(t, "test-token")

	resp, err := http.Get(env.server.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated health request to return 401, got %d", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, env.server.URL+"/api/health", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected authenticated health request to return 200, got %d", resp.StatusCode)
	}
}

func TestBearerAuthDoesNotProtectDashboard(t *testing.T) {
	env := setupTestEnvWithAuthToken(t, "test-token")

	resp, err := http.Get(env.server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard request without token to return 200, got %d", resp.StatusCode)
	}
}

func TestBearerAuthDisabledWhenTokenEmpty(t *testing.T) {
	env := setupTestEnvWithAuthToken(t, "")

	resp, err := http.Get(env.server.URL + "/api/policies")
	if err != nil {
		t.Fatalf("GET /api/policies: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected empty auth token to leave API unprotected, got %d", resp.StatusCode)
	}
}

func TestServerCloseDrainsAuditLog(t *testing.T) {
	env := setupTestEnv(t)

	for i := 0; i < 5; i++ {
		env.api.audit("test", map[string]any{"index": i})
	}

	env.api.Close()
	env.api.Close()

	count, err := env.audit.Count()
	if err != nil {
		t.Fatalf("counting audit entries: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected 5 drained audit entries, got %d", count)
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
	violation, ok := compliance["violation"].(map[string]any)
	if !ok {
		t.Fatal("violation has unexpected shape")
	}
	txID, ok := violation["transaction_id"].(string)
	if !ok || txID == "" {
		t.Fatalf("expected violation transaction_id to be populated, got %v", violation["transaction_id"])
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

func TestSettlePathExtractionFailure(t *testing.T) {
	env := setupTestEnvWithExtractor(t, rejectingPathExtractor{})

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
		PolicyID: "test-policy",
		RawPath:  compliantPath(t),
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d: %v", resp.StatusCode, result)
	}
	if result["code"] != "INVALID_REQUEST" {
		t.Fatalf("expected code INVALID_REQUEST, got %v", result["code"])
	}
	if !strings.Contains(result["error"].(string), "path extraction failed") {
		t.Fatalf("expected path extraction error, got %v", result["error"])
	}

	ledgerResp, err := http.Get(env.server.URL + "/api/ledger")
	if err != nil {
		t.Fatalf("GET /api/ledger: %v", err)
	}
	defer ledgerResp.Body.Close()
	var lr LedgerResponse
	if err := json.NewDecoder(ledgerResp.Body).Decode(&lr); err != nil {
		t.Fatalf("decoding ledger response: %v", err)
	}
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

func TestRotateKeyPreservesVerifiableReceiptChain(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	gen, err := receipt.NewGeneratorFromFile(keyPath)
	if err != nil {
		t.Fatalf("creating generator from file: %v", err)
	}
	env := setupTestEnvWithGeneratorReceiptStoreExtractorAndOptions(
		t,
		gen,
		receipt.NewMemoryStore(),
		&scion.MockPathExtractor{},
		WithAdminToken("admin-token"),
		WithOracleKeyPath(keyPath),
	)

	resp, result := postSettle(t, env.server.URL, SettleRequest{
		TransactionID: "tx-before-rotation",
		From:          "CH",
		To:            "EU",
		Amount:        100,
		Currency:      "CHF",
		PolicyID:      "test-policy",
		RawPath:       compliantPath(t),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first settle expected 200, got %d: %v", resp.StatusCode, result)
	}

	rotateReq, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/rotate-key", nil)
	if err != nil {
		t.Fatalf("creating rotate request: %v", err)
	}
	rotateReq.Header.Set("X-JurisPath-Admin-Token", "admin-token")
	rotateResp, err := http.DefaultClient.Do(rotateReq)
	if err != nil {
		t.Fatalf("POST /api/rotate-key: %v", err)
	}
	defer rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate expected 200, got %d", rotateResp.StatusCode)
	}
	var rotateResult RotateKeyResponse
	if err := json.NewDecoder(rotateResp.Body).Decode(&rotateResult); err != nil {
		t.Fatalf("decoding rotate response: %v", err)
	}
	if bytes.Equal(rotateResult.OldOraclePublicKey, rotateResult.NewOraclePublicKey) {
		t.Fatal("expected rotated oracle public key to change")
	}
	if rotateResult.ArchivedKeyPath == "" {
		t.Fatal("expected archived key path")
	}
	if _, err := os.Stat(rotateResult.ArchivedKeyPath); err != nil {
		t.Fatalf("expected archived key file to exist: %v", err)
	}

	resp, result = postSettle(t, env.server.URL, SettleRequest{
		TransactionID: "tx-after-rotation",
		From:          "CH",
		To:            "EU",
		Amount:        100,
		Currency:      "CHF",
		PolicyID:      "test-policy",
		RawPath:       compliantPath(t),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second settle expected 200, got %d: %v", resp.StatusCode, result)
	}

	verifyResp, err := http.Get(env.server.URL + "/api/verify-chain")
	if err != nil {
		t.Fatalf("GET /api/verify-chain: %v", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify-chain expected 200, got %d", verifyResp.StatusCode)
	}
	var chain VerifyChainResponse
	if err := json.NewDecoder(verifyResp.Body).Decode(&chain); err != nil {
		t.Fatalf("decoding verify-chain response: %v", err)
	}
	if chain.ChainLength != 2 {
		t.Fatalf("expected chain length 2, got %d", chain.ChainLength)
	}
	if len(chain.OraclePublicKeys) != 2 {
		t.Fatalf("expected 2 oracle public keys, got %d", len(chain.OraclePublicKeys))
	}
	if len(chain.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(chain.Receipts))
	}
	if bytes.Equal(chain.Receipts[0].OraclePublicKey, chain.Receipts[1].OraclePublicKey) {
		t.Fatal("expected receipts across rotation to carry different oracle keys")
	}

	validator := security.NewReceiptValidator(5 * time.Minute)
	for _, key := range chain.OraclePublicKeys {
		validator.TrustOracleKey(key)
	}
	if err := validator.ValidateReceiptChain(chain.Receipts); err != nil {
		t.Fatalf("rotated receipt chain should validate: %v", err)
	}
}

func TestRotateKeyRequiresAdminToken(t *testing.T) {
	env := setupTestEnvWithGeneratorReceiptStoreExtractorAndOptions(
		t,
		mustGenerator(t),
		receipt.NewMemoryStore(),
		&scion.MockPathExtractor{},
	)

	resp, err := http.Post(env.server.URL+"/api/rotate-key", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/rotate-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 before rotation configuration is inspected, got %d", resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["code"] != "FORBIDDEN" {
		t.Fatalf("expected code FORBIDDEN, got %v", result["code"])
	}
}

func TestRotateKeyRejectsWrongAdminToken(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "oracle.key")
	gen, err := receipt.NewGeneratorFromFile(keyPath)
	if err != nil {
		t.Fatalf("creating generator from file: %v", err)
	}
	env := setupTestEnvWithGeneratorReceiptStoreExtractorAndOptions(
		t,
		gen,
		receipt.NewMemoryStore(),
		&scion.MockPathExtractor{},
		WithAdminToken("admin-token"),
		WithOracleKeyPath(keyPath),
	)

	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/rotate-key", nil)
	if err != nil {
		t.Fatalf("creating rotate request: %v", err)
	}
	req.Header.Set("X-JurisPath-Admin-Token", "wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/rotate-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
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

func TestReceiptPersistenceFailureAudits(t *testing.T) {
	tests := []struct {
		name        string
		call        func(t *testing.T, url string)
		wantContext string
	}{
		{
			name: "check endpoint persists failure audit and returns internal error",
			call: func(t *testing.T, url string) {
				body, err := json.Marshal(CheckRequest{
					TransactionID: "tx-check-fail",
					PolicyID:      "test-policy",
					RawPath:       compliantPath(t),
				})
				if err != nil {
					t.Fatalf("marshal request: %v", err)
				}
				resp, err := http.Post(url+"/api/check", "application/json", bytes.NewReader(body))
				if err != nil {
					t.Fatalf("POST /api/check: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusInternalServerError {
					t.Fatalf("expected 500, got %d", resp.StatusCode)
				}
			},
			wantContext: "check",
		},
		{
			name: "settle endpoint persists failure audit and still returns success",
			call: func(t *testing.T, url string) {
				resp, result := postSettle(t, url, SettleRequest{
					TransactionID: "tx-settle-fail",
					From:          "CH",
					To:            "EU",
					Amount:        100,
					Currency:      "CHF",
					PolicyID:      "test-policy",
					RawPath:       compliantPath(t),
				})
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("expected 200, got %d: %v", resp.StatusCode, result)
				}
				consensus, ok := result["consensus"].(map[string]any)
				if !ok || consensus["confirmed"] != true {
					t.Fatalf("expected consensus.confirmed=true, got %v", result["consensus"])
				}
				compliance, ok := result["compliance"].(map[string]any)
				if !ok || compliance["receipt"] == nil {
					t.Fatalf("expected compliance receipt in response, got %v", result["compliance"])
				}
				if result["receipt_persisted"] != false {
					t.Fatalf("expected receipt_persisted=false, got %v", result["receipt_persisted"])
				}
				if result["persistence_warning"] == "" {
					t.Fatalf("expected non-empty persistence_warning, got %v", result["persistence_warning"])
				}
			},
			wantContext: "settle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupTestEnvWithReceiptStore(t, &failingAppendReceiptStore{
				inner: receipt.NewMemoryStore(),
				err:   errors.New("disk full"),
			})

			tt.call(t, env.server.URL)
			details := waitForAuditEvent(t, env.audit, "receipt_persist_failure", 2*time.Second)

			if details["context"] != tt.wantContext {
				t.Fatalf("context = %v, want %q", details["context"], tt.wantContext)
			}
			if details["code"] != "RECEIPT_PERSISTENCE_FAILED" {
				t.Fatalf("code = %v, want RECEIPT_PERSISTENCE_FAILED", details["code"])
			}
			if details["error"] != "disk full" {
				t.Fatalf("error = %v, want %q", details["error"], "disk full")
			}
			if details["policy_id"] != "test-policy" {
				t.Fatalf("policy_id = %v, want test-policy", details["policy_id"])
			}
			if details["receipt_id"] == "" {
				t.Fatal("expected non-empty receipt_id")
			}
		})
	}
}

func waitForAuditEvent(t *testing.T, al *audit.AuditLog, eventType string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		count, err := al.Count()
		if err != nil {
			t.Fatalf("counting audit entries: %v", err)
		}
		entries, err := al.List(0, count)
		if err != nil {
			t.Fatalf("listing audit entries: %v", err)
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i].EventType != eventType {
				continue
			}
			var details map[string]any
			if err := json.Unmarshal(entries[i].Details, &details); err != nil {
				t.Fatalf("unmarshaling audit details: %v", err)
			}
			return details
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for audit event type %q", eventType)
	return nil
}

func postCheck(t *testing.T, url string, req CheckRequest) (*http.Response, map[string]any) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshaling check request: %v", err)
	}
	resp, err := http.Post(url+"/api/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/check: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding check response: %v", err)
	}
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

func TestCheckPathExtractionFailure(t *testing.T) {
	env := setupTestEnvWithExtractor(t, rejectingPathExtractor{})

	resp, result := postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-extract-fail-1",
		PolicyID:      "test-policy",
		RawPath:       compliantPath(t),
	})

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d: %v", resp.StatusCode, result)
	}
	if result["code"] != "INVALID_REQUEST" {
		t.Fatalf("expected code INVALID_REQUEST, got %v", result["code"])
	}
	if !strings.Contains(result["error"].(string), "path extraction failed") {
		t.Fatalf("expected path extraction error, got %v", result["error"])
	}
}

// --- List / read-only handlers ---

func TestListReceipts_Empty(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/receipts")
	if err != nil {
		t.Fatalf("GET /api/receipts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var receipts []any
	json.NewDecoder(resp.Body).Decode(&receipts)
	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts, got %d", len(receipts))
	}
}

func TestListReceipts_AfterCheck(t *testing.T) {
	env := setupTestEnv(t)

	// Issue a compliant check to generate a receipt
	postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-1",
		PolicyID:      "test-policy",
		RawPath:       compliantPath(t),
	})

	resp, err := http.Get(env.server.URL + "/api/receipts")
	if err != nil {
		t.Fatalf("GET /api/receipts: %v", err)
	}
	defer resp.Body.Close()

	var receipts []any
	json.NewDecoder(resp.Body).Decode(&receipts)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
}

func TestListViolations_Empty(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/violations")
	if err != nil {
		t.Fatalf("GET /api/violations: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var violations []any
	json.NewDecoder(resp.Body).Decode(&violations)
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(violations))
	}
}

func TestListViolations_AfterCheck(t *testing.T) {
	env := setupTestEnv(t)

	postCheck(t, env.server.URL, CheckRequest{
		TransactionID: "tx-bad",
		PolicyID:      "test-policy",
		RawPath:       nonCompliantPath(t),
	})

	resp, err := http.Get(env.server.URL + "/api/violations")
	if err != nil {
		t.Fatalf("GET /api/violations: %v", err)
	}
	defer resp.Body.Close()

	var violations []any
	json.NewDecoder(resp.Body).Decode(&violations)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

func TestListPolicies(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/policies")
	if err != nil {
		t.Fatalf("GET /api/policies: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var policies []map[string]any
	json.NewDecoder(resp.Body).Decode(&policies)
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0]["id"] != "test-policy" {
		t.Fatalf("expected policy id 'test-policy', got %v", policies[0]["id"])
	}
}

func TestFilterPaths(t *testing.T) {
	env := setupTestEnv(t)

	req := FilterPathsRequest{
		PolicyID: "test-policy",
		Paths: []model.SCIONPath{
			{Hops: []model.ASHop{{IA: "1-ff00:0:110", ISD: 1}, {IA: "2-ff00:0:210", ISD: 2}}, Fingerprint: "ok"},
			{Hops: []model.ASHop{{IA: "1-ff00:0:110", ISD: 1}, {IA: "3-ff00:0:310", ISD: 3}}, Fingerprint: "bad"},
		},
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(env.server.URL+"/api/filter-paths", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/filter-paths: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	compliant := result["compliant"].([]any)
	nonCompliant := result["non_compliant"].([]any)
	if len(compliant) != 1 {
		t.Fatalf("expected 1 compliant, got %d", len(compliant))
	}
	if len(nonCompliant) != 1 {
		t.Fatalf("expected 1 non-compliant, got %d", len(nonCompliant))
	}
}

func TestFilterPaths_UnknownPolicy(t *testing.T) {
	env := setupTestEnv(t)

	req := FilterPathsRequest{PolicyID: "nope", Paths: []model.SCIONPath{}}
	body, _ := json.Marshal(req)
	resp, err := http.Post(env.server.URL+"/api/filter-paths", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/filter-paths: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestLedger(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/ledger")
	if err != nil {
		t.Fatalf("GET /api/ledger: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var lr LedgerResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	if len(lr.Validators) != 3 {
		t.Fatalf("expected 3 validators, got %d", len(lr.Validators))
	}
}

func TestTransactions_Empty(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/transactions")
	if err != nil {
		t.Fatalf("GET /api/transactions: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var txs []any
	json.NewDecoder(resp.Body).Decode(&txs)
	if len(txs) != 0 {
		t.Fatalf("expected 0 transactions, got %d", len(txs))
	}
}

func TestTransactions_AfterSettle(t *testing.T) {
	env := setupTestEnv(t)

	postSettle(t, env.server.URL, SettleRequest{
		From: "CH", To: "EU", Amount: 100, Currency: "CHF",
		PolicyID: "test-policy", RawPath: compliantPath(t),
	})

	resp, err := http.Get(env.server.URL + "/api/transactions")
	if err != nil {
		t.Fatalf("GET /api/transactions: %v", err)
	}
	defer resp.Body.Close()

	var txs []any
	json.NewDecoder(resp.Body).Decode(&txs)
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
}

func TestSSE_ConnectsAndDisconnects(t *testing.T) {
	env := setupTestEnv(t)

	// SSE streams indefinitely — use a short-lived context to verify the
	// endpoint accepts connections without hanging the test suite.
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", env.server.URL+"/api/events", nil)

	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		errCh <- err
	}()

	// Give the handler time to start, then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()

	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
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
	if result["code"] != "INVALID_REQUEST" {
		t.Fatalf("expected code INVALID_REQUEST, got %v", result["code"])
	}
}
