package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/violation"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config error: %v", err)
	}

	// Load jurisdiction policies
	policies, err := policy.LoadAllFromDir(cfg.PolicyDir)
	if err != nil {
		log.Fatalf("loading policies: %v", err)
	}
	log.Printf("loaded %d policies", len(policies))

	// Initialize receipt generator with fresh Ed25519 key pair
	gen, err := receipt.NewGenerator()
	if err != nil {
		log.Fatalf("creating receipt generator: %v", err)
	}
	log.Printf("oracle public key: %x", gen.PublicKey())

	// Use mock path extractor for now; swap to real snet extractor when
	// running on a SCION network
	extractor := &scion.MockPathExtractor{}

	// Initialize DLT ledger with three validators (one per ISD)
	validators := []dlt.ValidatorState{
		{
			ID:      "CH",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 10000, "EUR": 5000},
		},
		{
			ID:      "EU",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 5000, "EUR": 10000},
		},
		{
			ID:      "X",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 1000, "EUR": 1000},
		},
	}
	ledger := dlt.NewLedger(validators)
	consensus := dlt.NewConsensusEngine(ledger, validators)
	log.Printf("DLT ledger initialized with %d validators", len(validators))

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("creating data dir: %v", err)
	}

	// Initialize persistent stores
	receiptStore, err := receipt.NewBoltStore(filepath.Join(cfg.DataDir, "receipts.db"))
	if err != nil {
		log.Fatalf("opening receipt store: %v", err)
	}
	defer receiptStore.Close()

	violationStore, err := violation.NewBoltViolationStore(filepath.Join(cfg.DataDir, "violations.db"))
	if err != nil {
		log.Fatalf("opening violation store: %v", err)
	}
	defer violationStore.Close()

	detector := violation.NewDetector(violationStore)

	// Start API server
	srv := api.NewServer(policies, gen, extractor, ledger, consensus, receiptStore, detector)
	log.Fatal(srv.ListenAndServe(cfg.ListenAddr))
}
