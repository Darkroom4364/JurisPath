package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/api"
	"github.com/jurispath/jurispath/internal/audit"
	"github.com/jurispath/jurispath/internal/dlt"
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/receipt"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/internal/security"
	"github.com/jurispath/jurispath/internal/violation"
)

const shutdownTimeout = 10 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	return runWithArgs(os.Args[1:])
}

func runWithArgs(args []string) int {
	if len(args) == 0 {
		return runServer()
	}
	return runCLICommand(args)
}

func runServer() int {
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
		return 1
	}
	slog.Debug("configuration loaded", "listen", cfg.ListenAddr, "policy_dir", cfg.PolicyDir, "data_dir", cfg.DataDir, "log_level", cfg.LogLevel)

	// Load jurisdiction policies
	policies, err := policy.LoadAllFromDir(cfg.PolicyDir)
	if err != nil {
		slog.Error("failed to load policies", "dir", cfg.PolicyDir, "error", err)
		return 1
	}
	slog.Info("policies loaded", "count", len(policies))
	for _, p := range policies {
		slog.Debug("policy registered", "id", p.ID, "mode", p.Mode, "allowed_isds", p.AllowedISDs)
	}

	// Initialize receipt generator with fresh Ed25519 key pair
	gen, err := receipt.NewGeneratorFromFile(cfg.OracleKeyPath)
	if err != nil {
		slog.Error("failed to create receipt generator", "error", err)
		return 1
	}
	slog.Info("receipt generator initialized", "public_key", gen.PublicKey())
	if cfg.TRCDir != "" {
		proofs, err := scion.NewTRCProofProvider(cfg.TRCDir)
		if err != nil {
			slog.Error("failed to load TRC proof provider", "dir", cfg.TRCDir, "error", err)
			return 1
		}
		gen.WithProofProvider(proofs)
		slog.Info("TRC-backed receipt proof provider initialized", "dir", cfg.TRCDir)
	} else {
		slog.Warn("using placeholder receipt ISD proofs; set JURISPATH_TRC_DIR for TRC-backed proof material")
	}
	if cfg.ThresholdK > 0 || cfg.ThresholdN > 0 {
		threshold, err := security.NewThresholdOracle(cfg.ThresholdK, cfg.ThresholdN)
		if err != nil {
			slog.Error("failed to initialize threshold receipt signer", "k", cfg.ThresholdK, "n", cfg.ThresholdN, "error", err)
			return 1
		}
		gen.WithThresholdSigner(threshold)
		slog.Info("threshold receipt signing enabled", "k", cfg.ThresholdK, "n", cfg.ThresholdN)
	}

	extractor := selectPathExtractor(cfg)
	if cfg.SCIONMode {
		slog.Warn("SCION mode rejects API-supplied raw_path until authenticated path evidence is wired")
	} else {
		slog.Warn("using mock path extractor - not connected to SCION daemon")
	}

	// Load validator topology from config file.
	validatorConfigs, err := config.LoadValidators(cfg.ValidatorsFile)
	if err != nil {
		slog.Error("failed to load validators", "path", cfg.ValidatorsFile, "error", err)
		return 1
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
			return 1
		}
		ctx := context.Background()
		network, _, err := scion.NewSCIONNetwork(ctx, cfg.SCIONDaemon)
		if err != nil {
			slog.Error("failed to initialize SCION network", "error", err)
			return 1
		}
		localAddr, err := dlt.ParseSCIONLocalAddr(cfg.ValidatorID, validators)
		if err != nil {
			slog.Error("failed to parse local SCION address", "error", err)
			return 1
		}
		conn, err := network.Listen(ctx, "udp", localAddr)
		if err != nil {
			slog.Error("failed to listen on SCION", "addr", localAddr, "error", err)
			return 1
		}
		peers, err := dlt.ParseSCIONPeers(cfg.ValidatorID, validators)
		if err != nil {
			conn.Close() //nolint:errcheck // cleanup on setup failure
			slog.Error("failed to parse SCION peers", "error", err)
			return 1
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
		return 1
	}

	// Initialize persistent stores
	receiptStore, err := receipt.NewBoltStore(filepath.Join(cfg.DataDir, "receipts.db"))
	if err != nil {
		slog.Error("failed to open receipt store", "error", err)
		return 1
	}
	defer receiptStore.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("receipt store opened", "path", filepath.Join(cfg.DataDir, "receipts.db"))

	if err := gen.SeedChain(receiptStore); err != nil {
		slog.Error("failed to seed receipt chain", "error", err)
		return 1
	}

	violationStore, err := violation.NewBoltViolationStore(filepath.Join(cfg.DataDir, "violations.db"))
	if err != nil {
		slog.Error("failed to open violation store", "error", err)
		return 1
	}
	defer violationStore.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("violation store opened", "path", filepath.Join(cfg.DataDir, "violations.db"))

	detector := violation.NewDetector(violationStore)

	auditLog, err := audit.NewAuditLog(filepath.Join(cfg.DataDir, "audit.db"))
	if err != nil {
		slog.Error("failed to open audit log", "error", err)
		return 1
	}
	defer auditLog.Close() //nolint:errcheck // shutdown cleanup
	slog.Debug("audit log opened", "path", filepath.Join(cfg.DataDir, "audit.db"))

	// Start API server
	if cfg.APIToken == "" {
		slog.Warn("JurisPath API authentication disabled by explicit local/demo opt-in")
	}
	srv := api.NewServer(
		policies,
		gen,
		extractor,
		ledger,
		consensus,
		receiptStore,
		detector,
		auditLog,
		cfg.DashboardDir,
		api.WithBearerToken(cfg.APIToken),
		api.WithAdminToken(cfg.AdminToken),
		api.WithOracleKeyPath(cfg.OracleKeyPath),
	)
	defer srv.Close()
	httpServer := api.NewHTTPServer(cfg.ListenAddr, srv.Handler())

	serverErr := make(chan error, 1)
	if cfg.TLSEnabled() {
		slog.Info("starting JurisPath HTTPS server", "addr", cfg.ListenAddr, "cert", cfg.TLSCert)
		go func() {
			serverErr <- httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		}()
	} else {
		// AllowInsecure must be true to reach here (enforced by cfg.Validate).
		slog.Warn("starting JurisPath HTTP server (no TLS — JURISPATH_INSECURE=true)", "addr", cfg.ListenAddr)
		go func() {
			serverErr <- httpServer.ListenAndServe()
		}()
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server exited", "error", err)
			return 1
		}
	case <-shutdownCtx.Done():
		stop()
		slog.Info("shutdown signal received", "addr", cfg.ListenAddr)

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("graceful server shutdown failed", "error", err)
			if closeErr := httpServer.Close(); closeErr != nil {
				slog.Error("forced server close failed", "error", closeErr)
			}
			return 1
		}

		if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server exited during shutdown", "error", err)
			return 1
		}
		slog.Info("server shut down gracefully", "addr", cfg.ListenAddr)
	}
	return 0
}

func selectPathExtractor(cfg *config.Config) scion.PathExtractor {
	if cfg.SCIONMode {
		return scion.NewRejectingPathExtractor("")
	}
	return &scion.MockPathExtractor{}
}
