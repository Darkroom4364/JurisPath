package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/internal/audit"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/pathcheck"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/violation"
	"github.com/jurispath/jurispath/pkg/model"
)

// ErrorResponse is the standard error envelope for all API errors.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message, Code: code})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("handler panic", "error", err, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Server is the JurisPath HTTP API.
type Server struct {
	mux           *http.ServeMux
	policies      []*policy.Policy
	checkers      map[string]*pathcheck.Checker    // policyID -> checker
	filters       map[string]*pathcheck.PathFilter // policyID -> filter
	receipts      receipt.Store
	generator     *receipt.Generator
	detector      *violation.Detector
	extractor     scion.PathExtractor
	ledger        *dlt.Ledger
	consensus     *dlt.ConsensusEngine
	auditLog      *audit.AuditLog
	auditCh       chan audit.AuditEntry
	auditFailures atomic.Uint64
	auditWG       sync.WaitGroup
	closeOnce     sync.Once
	startTime     time.Time
	dashboardDir  string
}

// NewServer creates the API server with all dependencies.
func NewServer(
	policies []*policy.Policy,
	gen *receipt.Generator,
	ext scion.PathExtractor,
	ledger *dlt.Ledger,
	consensus *dlt.ConsensusEngine,
	rs receipt.Store,
	det *violation.Detector,
	al *audit.AuditLog,
	dashboardDir string,
) *Server {
	s := &Server{
		mux:          http.NewServeMux(),
		policies:     policies,
		checkers:     make(map[string]*pathcheck.Checker),
		filters:      make(map[string]*pathcheck.PathFilter),
		receipts:     rs,
		generator:    gen,
		detector:     det,
		extractor:    ext,
		ledger:       ledger,
		consensus:    consensus,
		auditLog:     al,
		auditCh:      make(chan audit.AuditEntry, 4096),
		startTime:    time.Now(),
		dashboardDir: dashboardDir,
	}

	for _, p := range policies {
		s.checkers[p.ID] = pathcheck.NewChecker(p)
		s.filters[p.ID] = pathcheck.NewPathFilter(p)
	}

	// Start background audit writer
	s.auditWG.Add(1)
	go s.auditWriter()

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/check", s.handleCheck)
	s.mux.HandleFunc("POST /api/filter-paths", s.handleFilterPaths)
	s.mux.HandleFunc("GET /api/receipts", s.handleListReceipts)
	s.mux.HandleFunc("GET /api/violations", s.handleListViolations)
	s.mux.HandleFunc("GET /api/policies", s.handleListPolicies)
	s.mux.HandleFunc("GET /api/events", s.handleSSE)

	// Chain verification
	s.mux.HandleFunc("GET /api/verify-chain", s.handleVerifyChain)

	// DLT settlement endpoints
	s.mux.HandleFunc("POST /api/settle", s.handleSettle)
	s.mux.HandleFunc("GET /api/ledger", s.handleLedger)
	s.mux.HandleFunc("GET /api/transactions", s.handleTransactions)

	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Serve dashboard static files
	if s.dashboardDir != "" {
		s.mux.Handle("GET /", http.FileServer(http.Dir(s.dashboardDir)))
	}
}

func (s *Server) auditWriter() {
	defer s.auditWG.Done()
	for entry := range s.auditCh {
		if err := s.auditLog.Append(entry); err != nil {
			s.auditFailures.Add(1)
			slog.Error("audit write failed", "event_type", entry.EventType, "error", err)
		}
	}
}

func (s *Server) audit(eventType string, details any) {
	data, err := json.Marshal(details)
	if err != nil {
		slog.Error("failed to marshal audit details", "event_type", eventType, "error", err)
		return
	}
	entry := audit.AuditEntry{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Details:   data,
	}
	select {
	case s.auditCh <- entry:
	case <-time.After(50 * time.Millisecond):
		s.auditFailures.Add(1)
		slog.Error("audit channel full, dropping entry", "event_type", eventType)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	failures := s.auditFailures.Load()
	count, _ := s.receipts.Count()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"audit_healthy":  failures == 0,
		"audit_failures": failures,
		"receipt_count":  count,
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
	})
}

// Close drains the audit channel and waits for the writer goroutine to exit.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.auditCh)
		s.auditWG.Wait()
	})
}

// Handler returns the API handler with recovery middleware applied.
func (s *Server) Handler() http.Handler {
	return recoveryMiddleware(s.mux)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

// ListenAndServeTLS starts the HTTPS server with the given certificate
// and private key files.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	return http.ListenAndServeTLS(addr, certFile, keyFile, s.Handler())
}

// CheckRequest is the payload for POST /api/check.
type CheckRequest struct {
	TransactionID string `json:"transaction_id"`
	PolicyID      string `json:"policy_id"`
	RawPath       []byte `json:"raw_path"`
}

const maxBodySize = 1 << 20 // 1 MB

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("invalid check request body", "error", err, "remote", r.RemoteAddr)
		s.audit("check", map[string]any{"outcome": "error", "code": "INVALID_REQUEST", "error": err.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	slog.Debug("compliance check requested", "tx_id", req.TransactionID, "policy_id", req.PolicyID)

	checker, ok := s.checkers[req.PolicyID]
	if !ok {
		slog.Warn("unknown policy in check request", "policy_id", req.PolicyID, "tx_id", req.TransactionID)
		s.audit("check", map[string]any{"tx_id": req.TransactionID, "policy_id": req.PolicyID, "outcome": "error", "code": "UNKNOWN_POLICY"})
		writeError(w, http.StatusBadRequest, "UNKNOWN_POLICY", fmt.Sprintf("unknown policy: %s", req.PolicyID))
		return
	}

	path, err := scion.BuildSCIONPath(s.extractor, req.RawPath)
	if err != nil {
		slog.Error("path extraction failed", "tx_id", req.TransactionID, "error", err)
		s.audit("check", map[string]any{"tx_id": req.TransactionID, "policy_id": req.PolicyID, "outcome": "error", "code": "INVALID_REQUEST", "error": err.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", fmt.Sprintf("path extraction failed: %v", err))
		return
	}
	slog.Debug("path extracted", "tx_id", req.TransactionID, "hops", len(path.Hops), "fingerprint", path.Fingerprint)

	result, err := checker.Check(path)
	if err != nil {
		slog.Error("compliance check failed", "tx_id", req.TransactionID, "policy_id", req.PolicyID, "error", err)
		s.audit("check", map[string]any{"tx_id": req.TransactionID, "policy_id": req.PolicyID, "outcome": "error", "code": "INTERNAL_ERROR", "error": err.Error()})
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("check failed: %v", err))
		return
	}

	var resp model.PolicyResult
	if result.Compliant {
		rcpt, err := s.generator.Issue(req.TransactionID, req.PolicyID, path)
		if err != nil {
			slog.Error("receipt generation failed", "tx_id", req.TransactionID, "error", err)
			s.audit("check", map[string]any{"tx_id": req.TransactionID, "policy_id": req.PolicyID, "outcome": "error", "code": "INTERNAL_ERROR", "error": err.Error()})
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("receipt generation failed: %v", err))
			return
		}
		if err := s.receipts.Append(rcpt); err != nil {
			slog.Error("failed to persist receipt", "tx_id", req.TransactionID, "receipt_id", rcpt.ID, "error", err)
			s.audit("check", map[string]any{"tx_id": req.TransactionID, "policy_id": req.PolicyID, "outcome": "error", "code": "INTERNAL_ERROR", "error": err.Error()})
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("persisting receipt failed: %v", err))
			return
		}
		slog.Info("compliance check passed", "tx_id", req.TransactionID, "policy_id", req.PolicyID, "receipt_id", rcpt.ID)
		s.audit("check", map[string]any{
			"tx_id":            req.TransactionID,
			"policy_id":        req.PolicyID,
			"compliant":        true,
			"path_fingerprint": path.Fingerprint,
			"receipt_id":       rcpt.ID,
		})
		resp = model.PolicyResult{Compliant: true, Receipt: rcpt}
	} else {
		v := s.detector.Record(req.TransactionID, req.PolicyID, result.ViolatedClause, path, result.OffendingHops)
		slog.Warn("compliance violation detected", "tx_id", req.TransactionID, "policy_id", req.PolicyID, "violation_id", v.ID, "clause", result.ViolatedClause)
		s.audit("check", map[string]any{
			"tx_id":            req.TransactionID,
			"policy_id":        req.PolicyID,
			"compliant":        false,
			"path_fingerprint": path.Fingerprint,
			"violation_id":     v.ID,
		})
		resp = model.PolicyResult{Compliant: false, Violation: v}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListReceipts(w http.ResponseWriter, _ *http.Request) {
	receipts, err := s.receipts.List()
	if err != nil {
		slog.Error("failed to list receipts", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("listing receipts: %v", err))
		return
	}
	slog.Debug("listing receipts", "count", len(receipts))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipts)
}

func (s *Server) handleListViolations(w http.ResponseWriter, _ *http.Request) {
	violations, err := s.detector.List()
	if err != nil {
		slog.Error("failed to list violations", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("listing violations: %v", err))
		return
	}
	slog.Debug("listing violations", "count", len(violations))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(violations)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, _ *http.Request) {
	slog.Debug("listing policies", "count", len(s.policies))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.policies)
}

// SettleRequest is the payload for POST /api/settle.
type SettleRequest struct {
	TransactionID string `json:"transaction_id,omitempty"` // optional client-supplied idempotency key
	From          string `json:"from"`
	To            string `json:"to"`
	Amount        int64  `json:"amount"`
	Currency      string `json:"currency"`
	PolicyID      string `json:"policy_id"`
	RawPath       []byte `json:"raw_path"`
}

// SettleResponse is returned by POST /api/settle.
type SettleResponse struct {
	Consensus  *dlt.ConsensusResult `json:"consensus"`
	Compliance *model.PolicyResult  `json:"compliance,omitempty"`
}

func (s *Server) handleSettle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	var req SettleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("invalid settle request body", "error", err, "remote", r.RemoteAddr)
		s.audit("settle", map[string]any{"outcome": "error", "code": "INVALID_REQUEST", "error": err.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	if req.From == "" || req.To == "" || req.Amount <= 0 || req.Currency == "" {
		slog.Warn("settle request missing required fields", "from", req.From, "to", req.To, "amount", req.Amount, "currency", req.Currency)
		s.audit("settle", map[string]any{"outcome": "error", "code": "INVALID_REQUEST", "from": req.From, "to": req.To})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "from, to, amount, and currency are required")
		return
	}
	if req.PolicyID == "" {
		s.audit("settle", map[string]any{"outcome": "error", "code": "POLICY_REQUIRED", "from": req.From, "to": req.To})
		writeError(w, http.StatusBadRequest, "POLICY_REQUIRED", "policy_id is required for settlement")
		return
	}
	if req.RawPath == nil {
		s.audit("settle", map[string]any{"outcome": "error", "code": "PATH_REQUIRED", "from": req.From, "to": req.To, "policy_id": req.PolicyID})
		writeError(w, http.StatusBadRequest, "PATH_REQUIRED", "raw_path is required for settlement")
		return
	}

	slog.Debug("settlement requested", "from", req.From, "to", req.To, "amount", req.Amount, "currency", req.Currency, "policy_id", req.PolicyID)

	// Step 1: Compliance check — must pass before consensus.
	checker, ok := s.checkers[req.PolicyID]
	if !ok {
		slog.Warn("unknown policy in settle request", "policy_id", req.PolicyID)
		s.audit("settle", map[string]any{"outcome": "error", "code": "UNKNOWN_POLICY", "policy_id": req.PolicyID, "from": req.From, "to": req.To})
		writeError(w, http.StatusBadRequest, "UNKNOWN_POLICY", fmt.Sprintf("unknown policy: %s", req.PolicyID))
		return
	}

	path, err := scion.BuildSCIONPath(s.extractor, req.RawPath)
	if err != nil {
		slog.Error("path extraction failed during settlement", "error", err)
		s.audit("settle", map[string]any{"outcome": "error", "code": "INVALID_REQUEST", "policy_id": req.PolicyID, "error": err.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", fmt.Sprintf("path extraction failed: %v", err))
		return
	}

	checkResult, err := checker.Check(path)
	if err != nil {
		slog.Error("compliance check failed during settlement", "error", err)
		s.audit("settle", map[string]any{"outcome": "error", "code": "INTERNAL_ERROR", "policy_id": req.PolicyID, "error": err.Error()})
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", fmt.Sprintf("compliance check failed: %v", err))
		return
	}

	if !checkResult.Compliant {
		v := s.detector.Record("", req.PolicyID, checkResult.ViolatedClause, path, checkResult.OffendingHops)
		slog.Warn("settlement blocked — path non-compliant", "policy_id", req.PolicyID, "violation_id", v.ID)
		s.audit("settle", map[string]any{
			"policy_id":    req.PolicyID,
			"compliant":    false,
			"outcome":      "non_compliant",
			"violation_id": v.ID,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(SettleResponse{
			Compliance: &model.PolicyResult{Compliant: false, Violation: v},
		})
		return
	}

	// Step 2: Path is compliant — proceed to consensus.
	txID := req.TransactionID
	if txID == "" {
		txID = uuid.New().String()
	}

	tx := &dlt.Transaction{
		ID:       txID,
		From:     req.From,
		To:       req.To,
		Amount:   req.Amount,
		Currency: req.Currency,
	}

	// Atomically submit + run consensus under one engine lock.
	existing, result, submitErr := s.consensus.SubmitAndRunRound(tx)
	if existing != nil {
		// Transaction already exists
		switch existing.Status {
		case dlt.TxConfirmed:
			slog.Debug("idempotent settle — already confirmed", "tx_id", txID)
			s.audit("settle", map[string]any{"tx_id": txID, "outcome": "idempotent", "status": "confirmed"})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SettleResponse{
				Consensus: &dlt.ConsensusResult{Confirmed: true, TxID: txID},
			})
			return
		case dlt.TxPending:
			s.audit("settle", map[string]any{"tx_id": txID, "outcome": "error", "code": "TX_PENDING"})
			writeError(w, http.StatusConflict, "TX_PENDING", fmt.Sprintf("transaction %s is pending", txID))
			return
		default: // TxRejected
			s.audit("settle", map[string]any{"tx_id": txID, "outcome": "error", "code": "DUPLICATE_TX"})
			writeError(w, http.StatusConflict, "DUPLICATE_TX", fmt.Sprintf("transaction ID %s was already used", txID))
			return
		}
	}
	if result == nil && submitErr != nil {
		// Submit validation failed (before round ran)
		slog.Warn("settlement submit failed", "tx_id", txID, "error", submitErr)
		s.audit("settle", map[string]any{"tx_id": txID, "outcome": "error", "code": "INVALID_REQUEST", "error": submitErr.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", submitErr.Error())
		return
	}
	resp := SettleResponse{Consensus: result}

	if submitErr != nil || (result != nil && !result.Confirmed) {
		slog.Warn("settlement consensus failed", "tx_id", txID, "error", submitErr)
		s.audit("settle", map[string]any{
			"tx_id":     txID,
			"policy_id": req.PolicyID,
			"compliant": true,
			"outcome":   "consensus_rejected",
			"from":      req.From,
			"to":        req.To,
			"amount":    req.Amount,
			"currency":  req.Currency,
		})
		// No receipt issued — consensus failed
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Step 3: Consensus confirmed — issue compliance receipt.
	rcpt, err := s.generator.Issue(txID, req.PolicyID, path)
	if err != nil {
		slog.Error("receipt generation failed during settlement", "tx_id", txID, "error", err)
		s.audit("settle", map[string]any{"tx_id": txID, "policy_id": req.PolicyID, "outcome": "error", "code": "INTERNAL_ERROR", "error": "receipt generation failed: " + err.Error()})
		// Settlement succeeded but receipt failed — still return consensus result
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	if err := s.receipts.Append(rcpt); err != nil {
		slog.Error("failed to persist receipt during settlement", "tx_id", txID, "error", err)
	}

	slog.Info("settlement completed", "tx_id", txID, "round", result.Round, "receipt_id", rcpt.ID)
	s.audit("settle", map[string]any{
		"tx_id":               txID,
		"policy_id":           req.PolicyID,
		"compliant":           true,
		"outcome":             "settled",
		"consensus_confirmed": true,
		"receipt_id":          rcpt.ID,
		"from":                req.From,
		"to":                  req.To,
		"amount":              req.Amount,
		"currency":            req.Currency,
	})
	resp.Compliance = &model.PolicyResult{Compliant: true, Receipt: rcpt}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// LedgerResponse is returned by GET /api/ledger.
type LedgerResponse struct {
	Validators []dlt.ValidatorState `json:"validators"`
	Round      uint64               `json:"current_round"`
}

func (s *Server) handleLedger(w http.ResponseWriter, _ *http.Request) {
	resp := LedgerResponse{
		Validators: s.ledger.GetValidators(),
		Round:      s.ledger.CurrentRound(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleTransactions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.ledger.ListTransactions())
}

// VerifyChainResponse is returned by GET /api/verify-chain.
type VerifyChainResponse struct {
	ChainLength     int                        `json:"chain_length"`
	OraclePublicKey []byte                     `json:"oracle_public_key"`
	Receipts        []*model.ComplianceReceipt `json:"receipts"`
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	const maxRange = 1000

	var fromSeq, toSeq uint64
	var useRange bool

	if v := r.URL.Query().Get("from_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid from_seq parameter")
			return
		}
		fromSeq = n
		useRange = true
	}
	if v := r.URL.Query().Get("to_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid to_seq parameter")
			return
		}
		toSeq = n
		useRange = true
	}

	if useRange {
		if toSeq < fromSeq {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "to_seq must be >= from_seq")
			return
		}
		if toSeq-fromSeq+1 > maxRange {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
				fmt.Sprintf("range exceeds maximum of %d receipts", maxRange))
			return
		}
	} else {
		fromSeq = 1
		toSeq = maxRange
	}

	receipts, err := s.receipts.ListRange(fromSeq, toSeq)
	if err != nil {
		slog.Error("failed to list receipts for chain verification", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load receipts")
		return
	}

	resp := VerifyChainResponse{
		ChainLength:     len(receipts),
		OraclePublicKey: s.generator.PublicKey(),
		Receipts:        receipts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// FilterPathsRequest is the payload for POST /api/filter-paths (Scenario C).
type FilterPathsRequest struct {
	PolicyID string            `json:"policy_id"`
	Paths    []model.SCIONPath `json:"paths"`
}

func (s *Server) handleFilterPaths(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	var req FilterPathsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("invalid filter-paths request body", "error", err, "remote", r.RemoteAddr)
		s.audit("filter", map[string]any{"outcome": "error", "code": "INVALID_REQUEST", "error": err.Error()})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	slog.Debug("path filtering requested", "policy_id", req.PolicyID, "candidate_paths", len(req.Paths))

	filter, ok := s.filters[req.PolicyID]
	if !ok {
		slog.Warn("unknown policy in filter-paths request", "policy_id", req.PolicyID)
		s.audit("filter", map[string]any{"outcome": "error", "code": "UNKNOWN_POLICY", "policy_id": req.PolicyID})
		writeError(w, http.StatusBadRequest, "UNKNOWN_POLICY", fmt.Sprintf("unknown policy: %s", req.PolicyID))
		return
	}

	result := filter.FilterPaths(req.Paths)

	slog.Debug("path filtering complete", "policy_id", req.PolicyID, "compliant", len(result.Compliant), "non_compliant", len(result.NonCompliant))
	s.audit("filter", map[string]any{
		"policy_id":     req.PolicyID,
		"candidate":     len(req.Paths),
		"compliant":     len(result.Compliant),
		"non_compliant": len(result.NonCompliant),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "streaming not supported")
		return
	}

	slog.Debug("SSE client connected", "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.detector.Subscribe()
	defer s.detector.Unsubscribe(ch)

	for {
		select {
		case v := <-ch:
			data, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: violation\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			slog.Debug("SSE client disconnected", "remote", r.RemoteAddr)
			return
		}
	}
}
