package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
)

func main() {
	baseURL := "http://localhost:8080"
	if v := os.Getenv("JURISPATH_DEMO_BASE_URL"); v != "" {
		baseURL = v
	}
	client := demoHTTPClient()

	// Scenario A: Compliant CHF-EUR settlement (ISD-CH -> ISD-EU only)
	fmt.Println("=== Scenario A: Compliant path (ISD-CH -> ISD-EU) ===")
	compliantHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}, // ISD-CH core
		{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"}, // ISD-CH non-core
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"}, // ISD-EU core
		{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"}, // ISD-EU non-core
	}
	sendCheck(client, baseURL, "tx-chf-eur-001", "chf-eur-settlement-v1", compliantHops)

	// Scenario B: Violation — path transits ISD-X
	fmt.Println("\n=== Scenario B: Non-compliant path (via ISD-X) ===")
	violatingHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}, // ISD-CH core
		{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}, // ISD-X (unauthorized!)
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"}, // ISD-EU core
	}
	sendCheck(client, baseURL, "tx-chf-eur-002", "chf-eur-settlement-v1", violatingHops)

	// Scenario C: Swiss-only settlement
	fmt.Println("\n=== Scenario C: Swiss-only settlement ===")
	swissHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
	}
	sendCheck(client, baseURL, "tx-chf-chf-001", "swiss-dlt-act-v1", swissHops)

	// Scenario D: Path pre-filtering (paper Scenario C)
	// A validator queries available SCION paths and JurisPath indicates which are compliant.
	fmt.Println("\n=== Scenario D: Path Pre-filtering ===")
	candidatePaths := []model.SCIONPath{
		{
			Fingerprint: "path-ch-eu-direct",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
				{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"},
			},
		},
		{
			Fingerprint: "path-via-isd-x",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
			},
		},
		{
			Fingerprint: "path-all-three-isds",
			Hops: []model.ASHop{
				{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
				{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"},
				{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"},
				{IA: "3-ff00:0:311", ISD: 3, AS: "ff00:0:311"},
			},
		},
	}
	sendFilterPaths(client, baseURL, "chf-eur-settlement-v1", candidatePaths)
}

func demoHTTPClient() *http.Client {
	if os.Getenv("JURISPATH_DEMO_INSECURE_TLS") != "true" {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &http.Transport{
			// #nosec G402 -- explicit local demo opt-in for self-signed certs.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func sendFilterPaths(client *http.Client, baseURL, policyID string, paths []model.SCIONPath) {
	req := api.FilterPathsRequest{
		PolicyID: policyID,
		Paths:    paths,
	}

	body, _ := json.Marshal(req)
	httpReq, err := newDemoRequest(baseURL+"/api/filter-paths", body)
	if err != nil {
		log.Fatalf("creating filter-paths request failed: %v", err)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Fatalf("filter-paths request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body cleanup

	var result struct {
		Compliant    []model.SCIONPath `json:"compliant"`
		NonCompliant []model.SCIONPath `json:"non_compliant"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("  Candidate paths: %d\n", len(paths))
	fmt.Printf("  Compliant: %d\n", len(result.Compliant))
	for _, p := range result.Compliant {
		fmt.Printf("    [PASS] %s (%d hops)\n", p.Fingerprint, len(p.Hops))
	}
	fmt.Printf("  Non-compliant (grayed out): %d\n", len(result.NonCompliant))
	for _, p := range result.NonCompliant {
		fmt.Printf("    [SKIP] %s (%d hops)\n", p.Fingerprint, len(p.Hops))
	}
}

func sendCheck(client *http.Client, baseURL, txID, policyID string, hops []model.ASHop) {
	rawPath, _ := scion.NewMockPath(hops)

	req := api.CheckRequest{
		TransactionID: txID,
		PolicyID:      policyID,
		RawPath:       rawPath,
	}

	body, _ := json.Marshal(req)
	httpReq, err := newDemoRequest(baseURL+"/api/check", body)
	if err != nil {
		log.Fatalf("creating request failed: %v", err)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body cleanup

	var result model.PolicyResult
	json.NewDecoder(resp.Body).Decode(&result)

	if result.Compliant {
		fmt.Printf("  COMPLIANT - Receipt ID: %s\n", result.Receipt.ID)
		fmt.Printf("  Signed by oracle, seq #%d\n", result.Receipt.SeqNo)
	} else {
		fmt.Printf("  VIOLATION - %s\n", result.Violation.ViolatedClause)
		fmt.Printf("  Severity: %s, offending hops: %d\n", result.Violation.Severity, len(result.Violation.OffendingHops))
	}
}

func newDemoRequest(url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := demoAPIToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func demoAPIToken() string {
	if token := os.Getenv("JURISPATH_DEMO_API_TOKEN"); token != "" {
		return token
	}
	return os.Getenv("JURISPATH_API_TOKEN")
}
