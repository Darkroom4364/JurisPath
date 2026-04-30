package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
)

const defaultCLIBaseURL = "http://localhost:8080"

type cliOptions struct {
	baseURL     string
	token       string
	insecureTLS bool
	out         io.Writer
	err         io.Writer
}

func runClientCommand(args []string) int {
	opts := defaultCLIOptions(os.Stdout, os.Stderr)
	if err := opts.run(args); err != nil {
		fmt.Fprintln(opts.err, "error:", err)
		return 1
	}
	return 0
}

func defaultCLIOptions(out, err io.Writer) *cliOptions {
	baseURL := os.Getenv("JURISPATH_CLI_BASE_URL")
	if baseURL == "" {
		baseURL = os.Getenv("JURISPATH_DEMO_BASE_URL")
	}
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
		insecureTLS: os.Getenv("JURISPATH_CLI_INSECURE_TLS") == "true" || os.Getenv("JURISPATH_DEMO_INSECURE_TLS") == "true",
		out:         out,
		err:         err,
	}
}

func (opts *cliOptions) run(args []string) error {
	if len(args) == 0 {
		printUsage(opts.err)
		return fmt.Errorf("missing command")
	}

	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(opts.err)
	fs.StringVar(&opts.baseURL, "base-url", opts.baseURL, "JurisPath server base URL")
	fs.StringVar(&opts.token, "token", opts.token, "API bearer token")
	fs.BoolVar(&opts.insecureTLS, "insecure-tls", opts.insecureTLS, "allow self-signed TLS certificates")

	switch command {
	case "health":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return opts.getJSON("/api/health")
	case "receipts":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return opts.getJSON("/api/receipts")
	case "violations":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return opts.getJSON("/api/violations")
	case "verify-chain":
		return opts.verifyChain(fs, args[1:])
	case "check":
		return opts.check(fs, args[1:])
	case "settle":
		return opts.settle(fs, args[1:])
	default:
		printUsage(opts.err)
		return fmt.Errorf("unknown command %q", command)
	}
}

func (opts *cliOptions) verifyChain(fs *flag.FlagSet, args []string) error {
	var fromSeq, toSeq uint64
	fs.Uint64Var(&fromSeq, "from-seq", 0, "first receipt sequence to verify")
	fs.Uint64Var(&toSeq, "to-seq", 0, "last receipt sequence to verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
	return opts.getJSON(path)
}

func (opts *cliOptions) check(fs *flag.FlagSet, args []string) error {
	var txID, policyID, pathSpec string
	fs.StringVar(&txID, "tx", "", "transaction ID")
	fs.StringVar(&policyID, "policy", "", "policy ID")
	fs.StringVar(&pathSpec, "path", "", "comma-separated IA path, e.g. 1-ff00:0:110,2-ff00:0:210")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if policyID == "" {
		return fmt.Errorf("--policy is required")
	}
	rawPath, err := rawPathFromSpec(pathSpec)
	if err != nil {
		return err
	}
	req := api.CheckRequest{TransactionID: txID, PolicyID: policyID, RawPath: rawPath}
	return opts.postJSON("/api/check", req)
}

func (opts *cliOptions) settle(fs *flag.FlagSet, args []string) error {
	var txID, from, to, currency, policyID, pathSpec string
	var amount int64
	fs.StringVar(&txID, "tx", "", "transaction ID")
	fs.StringVar(&from, "from", "", "source validator/account")
	fs.StringVar(&to, "to", "", "destination validator/account")
	fs.Int64Var(&amount, "amount", 0, "settlement amount")
	fs.StringVar(&currency, "currency", "", "settlement currency")
	fs.StringVar(&policyID, "policy", "", "policy ID")
	fs.StringVar(&pathSpec, "path", "", "comma-separated IA path, e.g. 1-ff00:0:110,2-ff00:0:210")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if from == "" || to == "" || amount <= 0 || currency == "" || policyID == "" {
		return fmt.Errorf("--from, --to, --amount, --currency, and --policy are required")
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
}

func (opts *cliOptions) getJSON(path string) error {
	req, err := opts.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return opts.do(req)
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

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  jurispath serve
  jurispath health [--base-url URL] [--token TOKEN]
  jurispath receipts [--base-url URL] [--token TOKEN]
  jurispath violations [--base-url URL] [--token TOKEN]
  jurispath verify-chain [--from-seq N] [--to-seq N] [--base-url URL] [--token TOKEN]
  jurispath check --policy POLICY --path IA[,IA...] [--tx TX] [--base-url URL] [--token TOKEN]
  jurispath settle --from FROM --to TO --amount N --currency CUR --policy POLICY --path IA[,IA...] [--tx TX] [--base-url URL] [--token TOKEN]

Environment:
  JURISPATH_CLI_BASE_URL       server base URL (default http://localhost:8080)
  JURISPATH_CLI_API_TOKEN      bearer token, falls back to JURISPATH_API_TOKEN
  JURISPATH_CLI_INSECURE_TLS   set true for local self-signed HTTPS`)
}
