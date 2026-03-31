package main

import (
	"log"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
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

	// Start API server
	srv := api.NewServer(policies, gen, extractor)
	log.Fatal(srv.ListenAndServe(cfg.ListenAddr))
}
