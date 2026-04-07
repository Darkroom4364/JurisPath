package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/pkg/daemon"

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

	// Connect to SCION daemon when configured; fall back to mock for dev/test.
	var extractor scion.PathExtractor
	if cfg.SCIONDaemonAddr != "" {
		ctx := context.Background()
		svc := daemon.NewService(cfg.SCIONDaemonAddr)
		conn, err := svc.Connect(ctx)
		if err != nil {
			log.Fatalf("connecting to SCION daemon at %s: %v", cfg.SCIONDaemonAddr, err)
		}
		defer conn.Close()
		extractor = scion.NewSnetPathExtractor(conn)
		log.Printf("using real SCION path extractor (daemon: %s)", cfg.SCIONDaemonAddr)
	} else {
		extractor = &scion.MockPathExtractor{}
		log.Print("WARNING: using mock path extractor (set SCION_DAEMON_ADDR for production)")
	}

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
