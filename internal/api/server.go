package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/pathcheck"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/violation"
	"github.com/jurispath/jurispath/pkg/model"
)

// Server is the JurisPath HTTP API.
type Server struct {
	mux       *http.ServeMux
	policies  []*policy.Policy
	checkers  map[string]*pathcheck.Checker // policyID -> checker
	receipts  receipt.Store
	generator *receipt.Generator
	detector  *violation.Detector
	extractor scion.PathExtractor
	ledger    *dlt.Ledger
	consensus *dlt.ConsensusEngine
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
) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		policies:  policies,
		checkers:  make(map[string]*pathcheck.Checker),
		receipts:  rs,
		generator: gen,
		detector:  det,
		extractor: ext,
		ledger:    ledger,
		consensus: consensus,
	}

	for _, p := range policies {
		s.checkers[p.ID] = pathcheck.NewChecker(p)
	}

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

	// DLT settlement endpoints
	s.mux.HandleFunc("POST /api/settle", s.handleSettle)
	s.mux.HandleFunc("GET /api/ledger", s.handleLedger)
	s.mux.HandleFunc("GET /api/transactions", s.handleTransactions)

	// Serve dashboard static files
	s.mux.Handle("GET /", http.FileServer(http.Dir("dashboard")))
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("JurisPath API listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

// CheckRequest is the payload for POST /api/check.
type CheckRequest struct {
	TransactionID string `json:"transaction_id"`
	PolicyID      string `json:"policy_id"`
	RawPath       []byte `json:"raw_path"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	checker, ok := s.checkers[req.PolicyID]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown policy: %s", req.PolicyID), http.StatusBadRequest)
		return
	}

	path, err := scion.BuildSCIONPath(s.extractor, req.RawPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("path extraction failed: %v", err), http.StatusBadRequest)
		return
	}

	result, err := checker.Check(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("check failed: %v", err), http.StatusInternalServerError)
		return
	}

	var resp model.PolicyResult
	if result.Compliant {
		rcpt, err := s.generator.Issue(req.TransactionID, req.PolicyID, path)
		if err != nil {
			http.Error(w, fmt.Sprintf("receipt generation failed: %v", err), http.StatusInternalServerError)
			return
		}
		if err := s.receipts.Append(rcpt); err != nil {
			http.Error(w, fmt.Sprintf("persisting receipt failed: %v", err), http.StatusInternalServerError)
			return
		}
		resp = model.PolicyResult{Compliant: true, Receipt: rcpt}
	} else {
		v := s.detector.Record(req.TransactionID, req.PolicyID, result.ViolatedClause, path, result.OffendingHops)
		resp = model.PolicyResult{Compliant: false, Violation: v}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListReceipts(w http.ResponseWriter, _ *http.Request) {
	receipts, err := s.receipts.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("listing receipts: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipts)
}

func (s *Server) handleListViolations(w http.ResponseWriter, _ *http.Request) {
	violations, err := s.detector.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("listing violations: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(violations)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.policies)
}

// SettleRequest is the payload for POST /api/settle.
type SettleRequest struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	PolicyID string `json:"policy_id,omitempty"` // optional: run compliance check
	RawPath  []byte `json:"raw_path,omitempty"`  // optional: SCION path for compliance
}

// SettleResponse is returned by POST /api/settle.
type SettleResponse struct {
	Consensus  *dlt.ConsensusResult `json:"consensus"`
	Compliance *model.PolicyResult  `json:"compliance,omitempty"`
}

func (s *Server) handleSettle(w http.ResponseWriter, r *http.Request) {
	var req SettleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.From == "" || req.To == "" || req.Amount <= 0 || req.Currency == "" {
		http.Error(w, "from, to, amount, and currency are required", http.StatusBadRequest)
		return
	}

	tx := &dlt.Transaction{
		ID:       uuid.New().String(),
		From:     req.From,
		To:       req.To,
		Amount:   req.Amount,
		Currency: req.Currency,
	}

	result, err := s.consensus.RunRound(tx)
	resp := SettleResponse{Consensus: result}

	if err != nil {
		// Transaction was rejected (e.g. insufficient balance). Return the
		// result with 200 so the caller can inspect the consensus outcome.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Optional compliance check on the network path.
	if req.PolicyID != "" && req.RawPath != nil {
		checker, ok := s.checkers[req.PolicyID]
		if ok {
			path, pathErr := scion.BuildSCIONPath(s.extractor, req.RawPath)
			if pathErr == nil {
				checkResult, checkErr := checker.Check(path)
				if checkErr == nil {
					var pr model.PolicyResult
					if checkResult.Compliant {
						rcpt, rcptErr := s.generator.Issue(tx.ID, req.PolicyID, path)
						if rcptErr == nil {
							if storeErr := s.receipts.Append(rcpt); storeErr == nil {
								pr = model.PolicyResult{Compliant: true, Receipt: rcpt}
							}
						}
					} else {
						v := s.detector.Record(tx.ID, req.PolicyID, checkResult.ViolatedClause, path, checkResult.OffendingHops)
						pr = model.PolicyResult{Compliant: false, Violation: v}
					}
					resp.Compliance = &pr
				}
			}
		}
	}

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

// FilterPathsRequest is the payload for POST /api/filter-paths (Scenario C).
type FilterPathsRequest struct {
	PolicyID string            `json:"policy_id"`
	Paths    []model.SCIONPath `json:"paths"`
}

func (s *Server) handleFilterPaths(w http.ResponseWriter, r *http.Request) {
	var req FilterPathsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Find the policy.
	var pol *policy.Policy
	for _, p := range s.policies {
		if p.ID == req.PolicyID {
			pol = p
			break
		}
	}
	if pol == nil {
		http.Error(w, fmt.Sprintf("unknown policy: %s", req.PolicyID), http.StatusBadRequest)
		return
	}

	filter := pathcheck.NewPathFilter(pol)
	result := filter.FilterPaths(req.Paths)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := s.detector.Subscribe()
	defer func() { /* cleanup */ }()

	for {
		select {
		case v := <-ch:
			data, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: violation\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
