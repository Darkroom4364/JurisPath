package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
)

func main() {
	baseURL := "http://localhost:8080"

	// Scenario A: Compliant CHF-EUR settlement (ISD-CH -> ISD-EU only)
	fmt.Println("=== Scenario A: Compliant path (ISD-CH -> ISD-EU) ===")
	compliantHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}, // ISD-CH core
		{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"}, // ISD-CH non-core
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"}, // ISD-EU core
		{IA: "2-ff00:0:211", ISD: 2, AS: "ff00:0:211"}, // ISD-EU non-core
	}
	sendCheck(baseURL, "tx-chf-eur-001", "chf-eur-settlement-v1", compliantHops)

	// Scenario B: Violation — path transits ISD-X
	fmt.Println("\n=== Scenario B: Non-compliant path (via ISD-X) ===")
	violatingHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"}, // ISD-CH core
		{IA: "3-ff00:0:310", ISD: 3, AS: "ff00:0:310"}, // ISD-X (unauthorized!)
		{IA: "2-ff00:0:210", ISD: 2, AS: "ff00:0:210"}, // ISD-EU core
	}
	sendCheck(baseURL, "tx-chf-eur-002", "chf-eur-settlement-v1", violatingHops)

	// Scenario C: Swiss-only settlement
	fmt.Println("\n=== Scenario C: Swiss-only settlement ===")
	swissHops := []model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
		{IA: "1-ff00:0:111", ISD: 1, AS: "ff00:0:111"},
	}
	sendCheck(baseURL, "tx-chf-chf-001", "swiss-dlt-act-v1", swissHops)
}

func sendCheck(baseURL, txID, policyID string, hops []model.ASHop) {
	rawPath, _ := scion.NewMockPath(hops)

	req := api.CheckRequest{
		TransactionID: txID,
		PolicyID:      policyID,
		RawPath:       rawPath,
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(baseURL+"/api/check", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

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
