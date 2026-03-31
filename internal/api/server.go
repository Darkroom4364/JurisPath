package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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
	receipts  *receipt.Store
	generator *receipt.Generator
	detector  *violation.Detector
	extractor scion.PathExtractor
}

// NewServer creates the API server with all dependencies.
func NewServer(
	policies []*policy.Policy,
	gen *receipt.Generator,
	ext scion.PathExtractor,
) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		policies:  policies,
		checkers:  make(map[string]*pathcheck.Checker),
		receipts:  receipt.NewStore(),
		generator: gen,
		detector:  violation.NewDetector(),
		extractor: ext,
	}

	for _, p := range policies {
		s.checkers[p.ID] = pathcheck.NewChecker(p)
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/check", s.handleCheck)
	s.mux.HandleFunc("GET /api/receipts", s.handleListReceipts)
	s.mux.HandleFunc("GET /api/violations", s.handleListViolations)
	s.mux.HandleFunc("GET /api/policies", s.handleListPolicies)
	s.mux.HandleFunc("GET /api/events", s.handleSSE)

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
		s.receipts.Append(rcpt)
		resp = model.PolicyResult{Compliant: true, Receipt: rcpt}
	} else {
		v := s.detector.Record(req.TransactionID, req.PolicyID, result.ViolatedClause, path, result.OffendingHops)
		resp = model.PolicyResult{Compliant: false, Violation: v}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListReceipts(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.receipts.List())
}

func (s *Server) handleListViolations(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.detector.List())
}

func (s *Server) handleListPolicies(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.policies)
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
