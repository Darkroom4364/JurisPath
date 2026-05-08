package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
	"github.com/spf13/cobra"
)

const defaultCLIBaseURL = "http://localhost:8080"

type cliOptions struct {
	baseURL     string
	token       string
	insecureTLS bool
	output      string
	out         io.Writer
	err         io.Writer
	server      func() int
}

type commandExitError struct {
	code int
}

func (e *commandExitError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.code)
}

func runCLICommand(args []string) int {
	opts := defaultCLIOptions(os.Stdout, os.Stderr)
	if err := opts.run(args); err != nil {
		var exitErr *commandExitError
		if errors.As(err, &exitErr) {
			return exitErr.code
		}
		fmt.Fprintln(opts.err, "error:", err)
		if isUsageError(err) {
			return 2
		}
		return 1
	}
	return 0
}

func isUsageError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unknown command") ||
		strings.Contains(msg, "accepts ") ||
		strings.Contains(msg, "required flag") ||
		strings.Contains(msg, "unknown flag")
}

func defaultCLIOptions(out, err io.Writer) *cliOptions {
	baseURL := os.Getenv("JURISPATH_CLI_BASE_URL")
	if baseURL == "" {
		baseURL = defaultCLIBaseURL
	}
	token := os.Getenv("JURISPATH_CLI_API_TOKEN")
	if token == "" {
		token = os.Getenv("JURISPATH_API_TOKEN")
	}
	return &cliOptions{
		baseURL:     baseURL,
		token:       token,
		insecureTLS: os.Getenv("JURISPATH_CLI_INSECURE_TLS") == "true",
		output:      "table",
		out:         out,
		err:         err,
		server:      runServer,
	}
}

func (opts *cliOptions) run(args []string) error {
	cmd := opts.newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(opts.out)
	cmd.SetErr(opts.err)
	return cmd.Execute()
}

func (opts *cliOptions) newRootCmd() *cobra.Command {
	if opts.output == "" {
		opts.output = "table"
	}

	root := &cobra.Command{
		Use:           "jurispath",
		Short:         "JurisPath path-policy oracle server and CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Help(); err != nil {
				return err
			}
			return fmt.Errorf("missing command")
		},
	}

	root.PersistentFlags().StringVar(&opts.baseURL, "base-url", opts.baseURL, "JurisPath server base URL")
	root.PersistentFlags().StringVar(&opts.token, "token", opts.token, "API bearer token")
	root.PersistentFlags().BoolVar(&opts.insecureTLS, "insecure-tls", opts.insecureTLS, "allow self-signed TLS certificates")
	root.PersistentFlags().StringVarP(&opts.output, "output", "o", opts.output, "output format: table or json")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if opts.output != "table" && opts.output != "json" {
			return fmt.Errorf("--output must be table or json")
		}
		return nil
	}

	root.AddCommand(opts.newServeCmd())
	root.AddCommand(opts.newStatusCmd())
	root.AddCommand(opts.newHealthCmd())
	root.AddCommand(opts.newPoliciesCmd())
	root.AddCommand(opts.newReceiptsCmd())
	root.AddCommand(opts.newViolationsCmd())
	root.AddCommand(opts.newVerifyChainCmd())
	root.AddCommand(opts.newCheckCmd())
	root.AddCommand(opts.newSettleCmd())
	root.AddCommand(opts.newFilterPathsCmd())
	root.AddCommand(opts.newDemoCmd())
	root.AddCommand(opts.newCompletionCmd())
	return root
}

func (opts *cliOptions) newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the JurisPath API server and dashboard",
		Args:  cobra.NoArgs,
		Example: `  jurispath serve
  JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true jurispath serve
  JURISPATH_TLS_CERT=deploy/certs/cert.pem JURISPATH_TLS_KEY=deploy/certs/key.pem JURISPATH_API_TOKEN=dev-token jurispath serve`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.server == nil {
				opts.server = runServer
			}
			if code := opts.server(); code != 0 {
				return &commandExitError{code: code}
			}
			return nil
		},
	}
}

func (opts *cliOptions) newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show server health and policy summary",
		Args:  cobra.NoArgs,
		Example: `  jurispath status
  jurispath status --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.status()
		},
	}
}

func (opts *cliOptions) newHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "health",
		Short:   "Show health details from the JurisPath server",
		Args:    cobra.NoArgs,
		Example: `  jurispath health -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.getHealth()
		},
	}
}

func (opts *cliOptions) newPoliciesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "policies",
		Short:   "List loaded corridor policies",
		Args:    cobra.NoArgs,
		Example: `  jurispath policies`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.getPolicies()
		},
	}
}

func (opts *cliOptions) newReceiptsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "receipts",
		Short:   "List path-policy receipts",
		Args:    cobra.NoArgs,
		Example: `  jurispath receipts -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.getReceipts()
		},
	}
}

func (opts *cliOptions) newViolationsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "violations",
		Short:   "List path-policy violations",
		Args:    cobra.NoArgs,
		Example: `  jurispath violations`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.getViolations()
		},
	}
}

func (opts *cliOptions) newVerifyChainCmd() *cobra.Command {
	var fromSeq, toSeq uint64
	cmd := &cobra.Command{
		Use:   "verify-chain",
		Short: "Verify the receipt hash chain",
		Args:  cobra.NoArgs,
		Example: `  jurispath verify-chain
  jurispath verify-chain --from-seq 10 --to-seq 25 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			values := url.Values{}
			if fromSeq > 0 {
				values.Set("from_seq", strconv.FormatUint(fromSeq, 10))
			}
			if toSeq > 0 {
				values.Set("to_seq", strconv.FormatUint(toSeq, 10))
			}
			path := "/api/verify-chain"
			if encoded := values.Encode(); encoded != "" {
				path += "?" + encoded
			}
			return opts.getVerifyChain(path)
		},
	}
	cmd.Flags().Uint64Var(&fromSeq, "from-seq", 0, "first receipt sequence to verify")
	cmd.Flags().Uint64Var(&toSeq, "to-seq", 0, "last receipt sequence to verify")
	return cmd
}

func (opts *cliOptions) newCheckCmd() *cobra.Command {
	var txID, policyID, pathSpec string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check whether path metadata matches a corridor policy",
		Args:  cobra.NoArgs,
		Example: `  jurispath check --policy eu-only --path "1-ff00:0:110,2-ff00:0:210"
  jurispath check --tx tx-123 --policy eu-only --path "1-ff00:0:110,2-ff00:0:210"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			rawPath, err := rawPathFromSpec(pathSpec)
			if err != nil {
				return err
			}
			req := api.CheckRequest{TransactionID: txID, PolicyID: policyID, RawPath: rawPath}
			return opts.postJSON("/api/check", req)
		},
	}
	cmd.Flags().StringVar(&txID, "tx", "", "transaction ID (optional; server assigns one when omitted)")
	cmd.Flags().StringVar(&policyID, "policy", "", "policy ID")
	cmd.Flags().StringVar(&pathSpec, "path", "", "comma-separated IA path, e.g. 1-ff00:0:110,2-ff00:0:210")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func (opts *cliOptions) status() error {
	var health map[string]any
	status, err := opts.getDecode("/api/health", &health)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("health returned HTTP %d", status)
	}
	var policies []policy.Policy
	status, err = opts.getDecode("/api/policies", &policies)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("policies returned HTTP %d", status)
	}
	summary := map[string]any{
		"base_url":       opts.baseURL,
		"audit_healthy":  health["audit_healthy"],
		"audit_failures": health["audit_failures"],
		"receipt_count":  health["receipt_count"],
		"uptime_seconds": health["uptime_seconds"],
		"policy_count":   len(policies),
	}
	if opts.output == "json" {
		return opts.printJSON(summary)
	}
	return opts.printStatus(summary)
}

func (opts *cliOptions) getHealth() error {
	var result map[string]any
	status, err := opts.getDecode("/api/health", &result)
	if err != nil {
		return err
	}
	if opts.output == "json" {
		if err := opts.printJSON(result); err != nil {
			return err
		}
	} else {
		if err := opts.printStatus(result); err != nil {
			return err
		}
	}
	return opts.statusError(status)
}

func (opts *cliOptions) getPolicies() error {
	var result []policy.Policy
	status, err := opts.getDecode("/api/policies", &result)
	if err != nil {
		return err
	}
	if opts.output == "json" {
		if err := opts.printJSON(result); err != nil {
			return err
		}
	} else {
		if err := opts.printPolicies(result); err != nil {
			return err
		}
	}
	return opts.statusError(status)
}

func (opts *cliOptions) getReceipts() error {
	var result []model.ComplianceReceipt
	status, err := opts.getDecode("/api/receipts", &result)
	if err != nil {
		return err
	}
	if opts.output == "json" {
		if err := opts.printJSON(result); err != nil {
			return err
		}
	} else {
		if err := opts.printReceipts(result); err != nil {
			return err
		}
	}
	return opts.statusError(status)
}

func (opts *cliOptions) getViolations() error {
	var result []model.Violation
	status, err := opts.getDecode("/api/violations", &result)
	if err != nil {
		return err
	}
	if opts.output == "json" {
		if err := opts.printJSON(result); err != nil {
			return err
		}
	} else {
		if err := opts.printViolations(result); err != nil {
			return err
		}
	}
	return opts.statusError(status)
}

func (opts *cliOptions) getVerifyChain(path string) error {
	var result api.VerifyChainResponse
	status, err := opts.getDecode(path, &result)
	if err != nil {
		return err
	}
	if opts.output == "json" {
		if err := opts.printJSON(result); err != nil {
			return err
		}
	} else {
		if err := opts.printVerifyChain(result); err != nil {
			return err
		}
	}
	return opts.statusError(status)
}

func (opts *cliOptions) newSettleCmd() *cobra.Command {
	var txID, from, to, currency, policyID, pathSpec string
	var amount int64
	cmd := &cobra.Command{
		Use:   "settle",
		Short: "Submit a settlement request and print the signed response",
		Args:  cobra.NoArgs,
		Example: `  jurispath settle --from CH --to EU --amount 100 --currency CHF --policy chf-eur-settlement-v1 --path "1-ff00:0:110,2-ff00:0:210"
  jurispath settle --tx tx-123 --from alice --to bob --amount 50 --currency CHF --policy swiss-dlt-act-v1 --path "1-ff00:0:110,1-ff00:0:111"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if amount <= 0 {
				return fmt.Errorf("--amount must be greater than 0")
			}
			rawPath, err := rawPathFromSpec(pathSpec)
			if err != nil {
				return err
			}
			req := api.SettleRequest{
				TransactionID: txID,
				From:          from,
				To:            to,
				Amount:        amount,
				Currency:      currency,
				PolicyID:      policyID,
				RawPath:       rawPath,
			}
			return opts.postJSON("/api/settle", req)
		},
	}
	cmd.Flags().StringVar(&txID, "tx", "", "transaction ID (optional idempotency key)")
	cmd.Flags().StringVar(&from, "from", "", "source validator/account")
	cmd.Flags().StringVar(&to, "to", "", "destination validator/account")
	cmd.Flags().Int64Var(&amount, "amount", 0, "settlement amount")
	cmd.Flags().StringVar(&currency, "currency", "", "settlement currency")
	cmd.Flags().StringVar(&policyID, "policy", "", "policy ID")
	cmd.Flags().StringVar(&pathSpec, "path", "", "comma-separated IA path, e.g. 1-ff00:0:110,2-ff00:0:210")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("amount")
	_ = cmd.MarkFlagRequired("currency")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func (opts *cliOptions) newFilterPathsCmd() *cobra.Command {
	var policyID, pathSpecs string
	cmd := &cobra.Command{
		Use:     "filter-paths",
		Short:   "Filter candidate SCION-style paths by corridor policy",
		Args:    cobra.NoArgs,
		Example: `  jurispath filter-paths --policy chf-eur-settlement-v1 --paths "1-ff00:0:110,2-ff00:0:210;1-ff00:0:110,3-ff00:0:310"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := pathsFromSpecs(pathSpecs)
			if err != nil {
				return err
			}
			req := api.FilterPathsRequest{PolicyID: policyID, Paths: paths}
			return opts.postJSON("/api/filter-paths", req)
		},
	}
	cmd.Flags().StringVar(&policyID, "policy", "", "policy ID")
	cmd.Flags().StringVar(&pathSpecs, "paths", "", "semicolon-separated candidate paths; each path is comma-separated IA hops")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("paths")
	return cmd
}

func (opts *cliOptions) newDemoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "demo",
		Short: "Run the built-in settlement demo scenarios",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.demo()
		},
	}
}

func (opts *cliOptions) newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Generate a shell completion script",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(opts.out)
			case "zsh":
				return cmd.Root().GenZshCompletion(opts.out)
			case "fish":
				return cmd.Root().GenFishCompletion(opts.out, true)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}

func (opts *cliOptions) demo() error {
	fmt.Fprintln(opts.out, "=== Scenario A: Compliant path (ISD-CH -> ISD-EU) ===")
	if err := opts.demoSettle("tx-chf-eur-001", "CH", "EU", 100, "CHF", "chf-eur-settlement-v1", "1-ff00:0:110,1-ff00:0:111,2-ff00:0:210,2-ff00:0:211"); err != nil {
		return err
	}

	fmt.Fprintln(opts.out, "\n=== Scenario B: Non-compliant path (via ISD-X) ===")
	if err := opts.demoSettle("tx-chf-eur-002", "CH", "EU", 100, "CHF", "chf-eur-settlement-v1", "1-ff00:0:110,3-ff00:0:310,2-ff00:0:210"); err != nil {
		return err
	}

	fmt.Fprintln(opts.out, "\n=== Scenario C: Swiss-only settlement ===")
	if err := opts.demoSettle("tx-chf-chf-001", "CH", "CH", 100, "CHF", "swiss-dlt-act-v1", "1-ff00:0:110,1-ff00:0:111"); err != nil {
		return err
	}

	fmt.Fprintln(opts.out, "\n=== Scenario D: Path Pre-filtering ===")
	return opts.demoFilterPaths("chf-eur-settlement-v1", strings.Join([]string{
		"1-ff00:0:110,1-ff00:0:111,2-ff00:0:210,2-ff00:0:211",
		"1-ff00:0:110,3-ff00:0:310,2-ff00:0:210",
		"1-ff00:0:110,3-ff00:0:310,2-ff00:0:210,3-ff00:0:311",
	}, ";"))
}

func (opts *cliOptions) demoSettle(txID, from, to string, amount int64, currency, policyID, pathSpec string) error {
	rawPath, err := rawPathFromSpec(pathSpec)
	if err != nil {
		return err
	}
	req := api.SettleRequest{
		TransactionID: txID,
		From:          from,
		To:            to,
		Amount:        amount,
		Currency:      currency,
		PolicyID:      policyID,
		RawPath:       rawPath,
	}
	var result api.SettleResponse
	status, err := opts.postDecode("/api/settle", req, &result)
	if err != nil {
		return err
	}
	if status == http.StatusUnprocessableEntity && result.Compliance != nil && result.Compliance.Violation != nil {
		fmt.Fprintf(opts.out, "  SETTLEMENT BLOCKED - %s\n", result.Compliance.Violation.ViolatedClause)
		fmt.Fprintf(opts.out, "  Severity: %s, offending hops: %d\n", result.Compliance.Violation.Severity, len(result.Compliance.Violation.OffendingHops))
		fmt.Fprintf(opts.out, "  Evidence: %s, proof: %s\n", result.Compliance.Violation.EvidenceClass, result.Compliance.Violation.ProofStatus)
		return nil
	}
	if status != http.StatusOK {
		return fmt.Errorf("settlement failed with HTTP %d", status)
	}
	if result.Consensus == nil || !result.Consensus.Confirmed {
		return fmt.Errorf("settlement was not confirmed")
	}
	if result.Compliance == nil || !result.Compliance.Compliant || result.Compliance.Receipt == nil {
		return fmt.Errorf("settlement response missing path-policy receipt")
	}
	fmt.Fprintf(opts.out, "  SETTLED - %s -> %s %d %s\n", from, to, amount, currency)
	fmt.Fprintf(opts.out, "  Consensus confirmed in round %d\n", result.Consensus.Round)
	fmt.Fprintf(opts.out, "  Receipt ID: %s, seq #%d\n", result.Compliance.Receipt.ID, result.Compliance.Receipt.SeqNo)
	fmt.Fprintf(opts.out, "  Evidence: %s, proof: %s\n", result.Compliance.Receipt.EvidenceClass, result.Compliance.Receipt.ProofStatus)
	fmt.Fprintf(opts.out, "  Path fingerprint: %s\n", result.Compliance.Receipt.Path.Fingerprint)
	if result.ReceiptPersisted != nil && !*result.ReceiptPersisted {
		fmt.Fprintf(opts.out, "  Persistence warning: %s\n", result.PersistenceWarning)
	}
	return nil
}

func (opts *cliOptions) demoFilterPaths(policyID, pathSpecs string) error {
	paths, err := pathsFromSpecs(pathSpecs)
	if err != nil {
		return err
	}
	req := api.FilterPathsRequest{PolicyID: policyID, Paths: paths}
	var result struct {
		Compliant    []model.SCIONPath `json:"compliant"`
		NonCompliant []model.SCIONPath `json:"non_compliant"`
	}
	status, err := opts.postDecode("/api/filter-paths", req, &result)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("filter-paths failed with HTTP %d", status)
	}
	fmt.Fprintf(opts.out, "  Candidate paths: %d\n", len(paths))
	fmt.Fprintf(opts.out, "  Compliant: %d\n", len(result.Compliant))
	for _, p := range result.Compliant {
		fmt.Fprintf(opts.out, "    [PASS] %s (%d hops)\n", p.Fingerprint, len(p.Hops))
	}
	fmt.Fprintf(opts.out, "  Non-compliant: %d\n", len(result.NonCompliant))
	for _, p := range result.NonCompliant {
		fmt.Fprintf(opts.out, "    [SKIP] %s (%d hops)\n", p.Fingerprint, len(p.Hops))
	}
	return nil
}

func (opts *cliOptions) getDecode(path string, result any) (int, error) {
	req, err := opts.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := opts.httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck // response body cleanup
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}

func (opts *cliOptions) postJSON(path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := opts.newRequest(http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return opts.do(req)
}

func (opts *cliOptions) postDecode(path string, payload any, result any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}
	req, err := opts.newRequest(http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := opts.httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck // response body cleanup
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}

func (opts *cliOptions) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	base, err := url.Parse(opts.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse path: %w", err)
	}
	req, err := http.NewRequest(method, base.ResolveReference(ref).String(), body)
	if err != nil {
		return nil, err
	}
	if opts.token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.token)
	}
	return req, nil
}

func (opts *cliOptions) do(req *http.Request) error {
	client := opts.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // response body cleanup

	var result any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("format response: %w", err)
	}
	fmt.Fprintln(opts.out, string(encoded))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (opts *cliOptions) statusError(status int) error {
	if status < 200 || status >= 300 {
		return fmt.Errorf("server returned HTTP %d", status)
	}
	return nil
}

func (opts *cliOptions) printJSON(result any) error {
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("format response: %w", err)
	}
	fmt.Fprintln(opts.out, string(encoded))
	return nil
}

func (opts *cliOptions) printStatus(values map[string]any) error {
	fmt.Fprintf(opts.out, "Base URL:       %v\n", valueOr(values, "base_url", opts.baseURL))
	fmt.Fprintf(opts.out, "Audit healthy:  %v\n", values["audit_healthy"])
	fmt.Fprintf(opts.out, "Audit failures: %v\n", values["audit_failures"])
	fmt.Fprintf(opts.out, "Receipts:       %v\n", values["receipt_count"])
	if _, ok := values["policy_count"]; ok {
		fmt.Fprintf(opts.out, "Policies:       %v\n", values["policy_count"])
	}
	fmt.Fprintf(opts.out, "Uptime:         %vs\n", values["uptime_seconds"])
	return nil
}

func (opts *cliOptions) printPolicies(policies []policy.Policy) error {
	w := tabwriter.NewWriter(opts.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tMODE\tVERSION\tALLOWED_ISDS")
	for _, p := range policies {
		fmt.Fprintf(w, "%s\t%s\t%d\t%v\n", p.ID, p.Mode, p.Version, p.AllowedISDs)
	}
	return w.Flush()
}

func (opts *cliOptions) printReceipts(receipts []model.ComplianceReceipt) error {
	w := tabwriter.NewWriter(opts.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tID\tTX\tPOLICY\tHOPS")
	for _, r := range receipts {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\n", r.SeqNo, r.ID, r.TransactionID, r.PolicyID, len(r.Path.Hops))
	}
	return w.Flush()
}

func (opts *cliOptions) printViolations(violations []model.Violation) error {
	w := tabwriter.NewWriter(opts.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tTX\tPOLICY\tSEVERITY\tOFFENDING_HOPS")
	for _, v := range violations {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", v.Timestamp.Format(time.RFC3339), v.TransactionID, v.PolicyID, v.Severity, len(v.OffendingHops))
	}
	return w.Flush()
}

func (opts *cliOptions) printVerifyChain(chain api.VerifyChainResponse) error {
	if _, err := fmt.Fprintf(opts.out, "Chain length: %d\n", chain.ChainLength); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(opts.out, "Oracle keys:  %d\n", len(chain.OraclePublicKeys)); err != nil {
		return err
	}
	w := tabwriter.NewWriter(opts.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tID\tTX\tPOLICY")
	for _, r := range chain.Receipts {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", r.SeqNo, r.ID, r.TransactionID, r.PolicyID)
	}
	return w.Flush()
}

func valueOr(values map[string]any, key string, fallback any) any {
	if value, ok := values[key]; ok {
		return value
	}
	return fallback
}

func (opts *cliOptions) httpClient() *http.Client {
	if !opts.insecureTLS {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// #nosec G402 -- explicit local CLI opt-in for self-signed certs.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func rawPathFromSpec(spec string) ([]byte, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("--path is required")
	}
	parts := strings.Split(spec, ",")
	hops := make([]model.ASHop, 0, len(parts))
	for _, part := range parts {
		ia := strings.TrimSpace(part)
		if ia == "" {
			continue
		}
		isdPart, _, ok := strings.Cut(ia, "-")
		if !ok {
			return nil, fmt.Errorf("path hop %q must be an IA like 1-ff00:0:110", ia)
		}
		isd, err := strconv.ParseUint(isdPart, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("path hop %q has invalid ISD: %w", ia, err)
		}
		hops = append(hops, model.ASHop{IA: ia, ISD: uint16(isd), AS: strings.TrimPrefix(ia, isdPart+"-")})
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("--path must contain at least one IA")
	}
	raw, err := scion.NewMockPath(hops)
	if err != nil {
		return nil, fmt.Errorf("build mock path: %w", err)
	}
	return raw, nil
}

func pathsFromSpecs(specs string) ([]model.SCIONPath, error) {
	if strings.TrimSpace(specs) == "" {
		return nil, fmt.Errorf("--paths is required")
	}
	parts := strings.Split(specs, ";")
	paths := make([]model.SCIONPath, 0, len(parts))
	extractor := &scion.MockPathExtractor{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := rawPathFromSpec(part)
		if err != nil {
			return nil, err
		}
		path, err := scion.BuildSCIONPath(extractor, raw)
		if err != nil {
			return nil, fmt.Errorf("build path: %w", err)
		}
		paths = append(paths, *path)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("--paths is required")
	}
	return paths, nil
}
