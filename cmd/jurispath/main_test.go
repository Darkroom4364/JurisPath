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
	"github.com/jurispath/jurispath/internal/policy"
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

func TestRunWithArgsServeRejectsExtraArgs(t *testing.T) {
	if code := runWithArgs([]string{"serve", "typo"}); code != 2 {
		t.Fatalf("runWithArgs serve typo code = %d, want 2", code)
	}
}

func TestDefaultCLIOptionsDoNotInheritDemoEnv(t *testing.T) {
	t.Setenv("JURISPATH_CLI_BASE_URL", "")
	t.Setenv("JURISPATH_CLI_INSECURE_TLS", "")
	t.Setenv("JURISPATH_DEMO_BASE_URL", "https://demo.example.test")
	t.Setenv("JURISPATH_DEMO_INSECURE_TLS", "true")

	opts := defaultCLIOptions(io.Discard, io.Discard)
	if opts.baseURL != defaultCLIBaseURL {
		t.Fatalf("baseURL = %q, want %q", opts.baseURL, defaultCLIBaseURL)
	}
	if opts.insecureTLS {
		t.Fatal("insecureTLS should not inherit JURISPATH_DEMO_INSECURE_TLS")
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
	opts := &cliOptions{baseURL: ts.URL, token: "test-token", output: "json", out: &out, err: io.Discard}
	if err := opts.run([]string{"health", "--output", "json"}); err != nil {
		t.Fatalf("health command: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if !strings.Contains(out.String(), "audit_healthy") {
		t.Fatalf("expected formatted JSON output, got %q", out.String())
	}
}

func TestCLIStatusPrintsSummary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health":
			json.NewEncoder(w).Encode(map[string]any{
				"audit_healthy":  true,
				"audit_failures": 0,
				"receipt_count":  3,
				"uptime_seconds": 12,
			})
		case "/api/policies":
			json.NewEncoder(w).Encode([]policy.Policy{{ID: "p1", Mode: "strict", Version: 1}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	opts := &cliOptions{baseURL: ts.URL, output: "table", out: &out, err: io.Discard}
	if err := opts.run([]string{"status"}); err != nil {
		t.Fatalf("status command: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Policies:") || !strings.Contains(got, "Receipts:") {
		t.Fatalf("expected status summary, got %q", got)
	}
}

func TestCLIPoliciesTableOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/policies" {
			t.Fatalf("path = %q, want /api/policies", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]policy.Policy{
			{ID: "chf-eur", Mode: "strict", Version: 2, AllowedISDs: []uint16{1, 2}},
		})
	}))
	defer ts.Close()

	var out bytes.Buffer
	opts := &cliOptions{baseURL: ts.URL, output: "table", out: &out, err: io.Discard}
	if err := opts.run([]string{"policies"}); err != nil {
		t.Fatalf("policies command: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "ID") || !strings.Contains(got, "MODE") || !strings.Contains(got, "chf-eur") {
		t.Fatalf("expected policies table, got %q", got)
	}
}

func TestPrintUsageShowsOutputFlagForReadCommands(t *testing.T) {
	var out bytes.Buffer
	printUsage(&out)
	got := out.String()
	for _, want := range []string{
		"jurispath status [--base-url URL] [--token TOKEN] [--output table|json]",
		"jurispath health [--base-url URL] [--token TOKEN] [--output table|json]",
		"jurispath policies [--base-url URL] [--token TOKEN] [--output table|json]",
		"jurispath receipts [--base-url URL] [--token TOKEN] [--output table|json]",
		"jurispath violations [--base-url URL] [--token TOKEN] [--output table|json]",
		"jurispath verify-chain [--from-seq N] [--to-seq N] [--base-url URL] [--token TOKEN] [--output table|json]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("usage missing %q in:\n%s", want, got)
		}
	}
}

func TestCLIHelpListsPolishedCommands(t *testing.T) {
	var out bytes.Buffer
	opts := defaultCLIOptions(&out, io.Discard)
	if err := opts.run([]string{"--help"}); err != nil {
		t.Fatalf("help command: %v", err)
	}
	got := out.String()
	for _, want := range []string{"Available Commands:", "completion", "settle", "verify-chain"} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q in:\n%s", want, got)
		}
	}
}

func TestCLICompletionGeneratesShellScript(t *testing.T) {
	var out bytes.Buffer
	opts := defaultCLIOptions(&out, io.Discard)
	if err := opts.run([]string{"completion", "zsh"}); err != nil {
		t.Fatalf("completion command: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "compdef _jurispath jurispath") {
		t.Fatalf("expected zsh completion script, got:\n%s", got)
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

func TestPathsFromSpecs(t *testing.T) {
	paths, err := pathsFromSpecs("1-ff00:0:110,2-ff00:0:210;1-ff00:0:110,3-ff00:0:310; ")
	if err != nil {
		t.Fatalf("pathsFromSpecs: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if len(paths[0].Hops) != 2 || len(paths[1].Hops) != 2 {
		t.Fatalf("unexpected paths: %+v", paths)
	}
}

func TestPathsFromSpecsRejectsOnlyEmptySegments(t *testing.T) {
	_, err := pathsFromSpecs(" ; ")
	if err == nil {
		t.Fatal("expected empty paths error")
	}
	if err.Error() != "--paths is required" {
		t.Fatalf("error = %q, want --paths is required", err)
	}
}

func TestCLIFilterPathsPostsRequest(t *testing.T) {
	var got api.FilterPathsRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/filter-paths" {
			t.Fatalf("path = %q, want /api/filter-paths", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"compliant": []model.SCIONPath{}, "non_compliant": []model.SCIONPath{}})
	}))
	defer ts.Close()

	var out bytes.Buffer
	opts := &cliOptions{baseURL: ts.URL, out: &out, err: io.Discard}
	err := opts.run([]string{
		"filter-paths",
		"--policy", "test-policy",
		"--paths", "1-ff00:0:110,2-ff00:0:210;1-ff00:0:110,3-ff00:0:310",
	})
	if err != nil {
		t.Fatalf("filter-paths command: %v", err)
	}
	if got.PolicyID != "test-policy" {
		t.Fatalf("PolicyID = %q, want test-policy", got.PolicyID)
	}
	if len(got.Paths) != 2 {
		t.Fatalf("expected 2 candidate paths, got %d", len(got.Paths))
	}
}
