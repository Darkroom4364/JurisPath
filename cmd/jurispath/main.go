package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/audit"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/violation"
)

func main() {
	cfg := config.Load()

	// Initialize structured logger
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	if err := cfg.Validate(); err != nil {
		slog.Error("config validation failed", "error", err)
		os.Exit(1)
	}
	slog.Debug("configuration loaded", "listen", cfg.ListenAddr, "policy_dir", cfg.PolicyDir, "data_dir", cfg.DataDir, "log_level", cfg.LogLevel)

	// Load jurisdiction policies
	policies, err := policy.LoadAllFromDir(cfg.PolicyDir)
	if err != nil {
		slog.Error("failed to load policies", "dir", cfg.PolicyDir, "error", err)
		os.Exit(1)
	}
	slog.Info("policies loaded", "count", len(policies))
	for _, p := range policies {
		slog.Debug("policy registered", "id", p.ID, "mode", p.Mode, "allowed_isds", p.AllowedISDs)
	}

	// Initialize receipt generator with fresh Ed25519 key pair
	gen, err := receipt.NewGeneratorFromFile(cfg.OracleKeyPath)
	if err != nil {
		slog.Error("failed to create receipt generator", "error", err)
		os.Exit(1)
	}
	slog.Info("receipt generator initialized", "public_key", gen.PublicKey())

	// Use mock path extractor for now; swap to real snet extractor when
	// running on a SCION network
	extractor := &scion.MockPathExtractor{}
	slog.Warn("using mock path extractor — not connected to SCION daemon")

	// Load validator topology from config file.
	validatorConfigs, err := config.LoadValidators(cfg.ValidatorsFile)
	if err != nil {
		slog.Error("failed to load validators", "path", cfg.ValidatorsFile, "error", err)
		os.Exit(1)
	}
	validators := make([]dlt.ValidatorState, len(validatorConfigs))
	for i, vc := range validatorConfigs {
		validators[i] = dlt.ValidatorState{
			ID:      vc.ID,
			Address: vc.Address,
			Balance: vc.Balance,
		}
	}

	var consensus *dlt.ConsensusEngine
	var ledger *dlt.Ledger
	if cfg.SCIONMode {
		// Multi-node mode: this process is one validator communicating
		// over real SCION/UDP connections.
		if cfg.ValidatorID == "" {
			slog.Error("JURISPATH_VALIDATOR_ID required in SCION mode")
			os.Exit(1)
		}
		ctx := context.Background()
		network, _, err := scion.NewSCIONNetwork(ctx, cfg.SCIONDaemon)
		if err != nil {
			slog.Error("failed to initialize SCION network", "error", err)
			os.Exit(1)
		}
		localAddr, err := dlt.ParseSCIONLocalAddr(cfg.ValidatorID, validators)
		if err != nil {
			slog.Error("failed to parse local SCION address", "error", err)
			os.Exit(1)
		}
		conn, err := network.Listen(ctx, "udp", localAddr)
		if err != nil {
			slog.Error("failed to listen on SCION", "addr", localAddr, "error", err)
			os.Exit(1)
		}
		peers, err := dlt.ParseSCIONPeers(cfg.ValidatorID, validators)
		if err != nil {
			conn.Close() //nolint:errcheck // cleanup on setup failure
			slog.Error("failed to parse SCION peers", "error", err)
			os.Exit(1)
		}
		transport := dlt.NewSCIONTransport(cfg.ValidatorID, conn, peers)
		// conn is now owned by transport; transport.Close() will close it.
		ledger = dlt.NewLedger(validators)
		consensus = dlt.NewConsensusEngineWithTransport(ledger, validators, transport)
		slog.Info("SCION consensus mode enabled", "validator", cfg.ValidatorID)
	} else {
		// Single-process mode: all validators run in one process with
		// in-memory transport.
		ledger = dlt.NewLedger(validators)
		consensus = dlt.NewConsensusEngine(ledger, validators)
	}
	slog.Info("DLT ledger initialized", "validators", len(validators))

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		slog.Error("failed to create data directory", "path", cfg.DataDir, "error", err)
		os.Exit(1)
	}

	// Initialize persistent stores
	receiptStore, err := receipt.NewBoltStore(filepath.Join(cfg.DataDir, "receipts.db"))
	if err != nil {
		slog.Error("failed to open receipt store", "error", err)
		os.Exit(1)
	}
	defer receiptStore.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("receipt store opened", "path", filepath.Join(cfg.DataDir, "receipts.db"))

	if err := gen.SeedChain(receiptStore); err != nil {
		slog.Error("failed to seed receipt chain", "error", err)
		os.Exit(1)
	}

	violationStore, err := violation.NewBoltViolationStore(filepath.Join(cfg.DataDir, "violations.db"))
	if err != nil {
		slog.Error("failed to open violation store", "error", err)
		os.Exit(1)
	}
	defer violationStore.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("violation store opened", "path", filepath.Join(cfg.DataDir, "violations.db"))

	detector := violation.NewDetector(violationStore)

	auditLog, err := audit.NewAuditLog(filepath.Join(cfg.DataDir, "audit.db"))
	if err != nil {
		slog.Error("failed to open audit log", "error", err)
		os.Exit(1)
	}
	defer auditLog.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("audit log opened", "path", filepath.Join(cfg.DataDir, "audit.db"))

	// Start API server
	srv := api.NewServer(policies, gen, extractor, ledger, consensus, receiptStore, detector, auditLog, cfg.DashboardDir)
	defer srv.Close()
	slog.Info("starting JurisPath API server", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(cfg.ListenAddr); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}
