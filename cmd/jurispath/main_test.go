package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
)

func TestSelectPathExtractor_NonSCIONUsesMock(t *testing.T) {
	extractor := selectPathExtractor(&config.Config{})
	if _, ok := extractor.(*scion.MockPathExtractor); !ok {
		t.Fatalf("got %T, want *scion.MockPathExtractor", extractor)
	}
}

func TestSelectPathExtractor_SCIONRejectsAPIRawPath(t *testing.T) {
	extractor := selectPathExtractor(&config.Config{SCIONMode: true})
	if _, ok := extractor.(*scion.RejectingPathExtractor); !ok {
		t.Fatalf("got %T, want *scion.RejectingPathExtractor", extractor)
	}

	raw, err := scion.NewMockPath([]model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scion.BuildSCIONPath(extractor, raw)
	if err == nil {
		t.Fatal("expected SCION mode extractor to reject API raw_path")
	}
	if !strings.Contains(err.Error(), "authenticated SCION session metadata") {
		t.Fatalf("error %q does not explain required path evidence", err)
	}
}

func TestRunWithArgsUnknownCommand(t *testing.T) {
	if code := runWithArgs([]string{"unknown"}); code != 2 {
		t.Fatalf("runWithArgs unknown code = %d, want 2", code)
	}
}

func TestRawPathFromSpec(t *testing.T) {
	raw, err := rawPathFromSpec("1-ff00:0:110, 2-ff00:0:210")
	if err != nil {
		t.Fatalf("rawPathFromSpec: %v", err)
	}
	path, err := scion.BuildSCIONPath(&scion.MockPathExtractor{}, raw)
	if err != nil {
		t.Fatalf("BuildSCIONPath: %v", err)
	}
	if len(path.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(path.Hops))
	}
	if path.Hops[0].ISD != 1 || path.Hops[1].ISD != 2 {
		t.Fatalf("unexpected ISDs: %+v", path.Hops)
	}
}

func TestCLIHealthAddsBearerTokenAndPrintsJSON(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/health" {
			t.Fatalf("path = %q, want /api/health", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"audit_healthy": true})
	}))
	defer ts.Close()

	var out bytes.Buffer
	opts := &cliOptions{baseURL: ts.URL, token: "test-token", out: &out, err: io.Discard}
	if err := opts.run([]string{"health"}); err != nil {
		t.Fatalf("health command: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if !strings.Contains(out.String(), "audit_healthy") {
		t.Fatalf("expected formatted JSON output, got %q", out.String())
	}
}

func TestCLISettlePostsRequest(t *testing.T) {
	var got api.SettleRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/settle" {
			t.Fatalf("path = %q, want /api/settle", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.SettleResponse{})
	}))
	defer ts.Close()

	var out bytes.Buffer
	opts := &cliOptions{baseURL: ts.URL, out: &out, err: io.Discard}
	err := opts.run([]string{
		"settle",
		"--from", "CH",
		"--to", "EU",
		"--amount", "100",
		"--currency", "CHF",
		"--policy", "test-policy",
		"--path", "1-ff00:0:110,2-ff00:0:210",
		"--tx", "tx-cli",
	})
	if err != nil {
		t.Fatalf("settle command: %v", err)
	}
	if got.TransactionID != "tx-cli" || got.From != "CH" || got.To != "EU" || got.Amount != 100 || got.Currency != "CHF" || got.PolicyID != "test-policy" {
		t.Fatalf("unexpected settle request: %+v", got)
	}
	if len(got.RawPath) == 0 {
		t.Fatal("expected raw_path to be populated")
	}
}
