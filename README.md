# JurisPath

Hackathon proof of concept for auditable SCION-style path checks before settlement-gateway messages are accepted. JurisPath issues signed path-policy receipts, records corridor policy violations, and provides CLI/API/dashboard surfaces for inspecting the receipt loop.

Inspired by the SCION/DLT settlement direction discussed in [SNB Working Paper 2025-15](https://www.snb.ch/en/publications/research/working-papers/2025/working_paper_2025_15), with the [Secure Swiss Finance Network (SSFN)](https://www.six-group.com/en/products-services/banking-services/ssfn.html) as a plausible deployment context.

## Current Status

The PoC is demo-ready. The main local flow, app-only Docker smoke, optional
SCION process smoke, metrics, tests, and documentation checks have been run
successfully. See [docs/project-status.md](docs/project-status.md) for the
current verification record and production boundary. The documentation index is
in [docs/README.md](docs/README.md).

Current receipts intentionally use `evidence_class=explicit-demo` and
`proof_status=unverified`. JurisPath demonstrates the path-policy decision and
receipt loop; it does not yet prove observed SCION dataplane traversal and it is
not a legal-compliance verdict.

## Quick Demo

```bash
make demo
```

For a 4-5 minute walkthrough, use
[docs/demo-script.md](docs/demo-script.md).

Optional checks:

```bash
make poc-metrics
make compose-smoke
make compose-smoke-scion
```

## Architecture

```
Client Request (HTTP POST /api/check)
        |
    API Server
        |
  Path Extractor ── extracts AS hops, computes SHA-256 fingerprint
        |
  Path-Policy Checker ── validates path against corridor policy
        |
   +----+----+
   |         |
Compliant  Violation
   |         |
Receipt    Violation Detector
Generator  (real-time SSE alerts)
   |
Ed25519-signed
Path-Policy Receipt
```

The oracle sits between a settlement workflow and SCION path selection. In local demo mode it checks explicit path metadata and labels that evidence as `explicit-demo` / `unverified`; in SCION mode API-supplied raw paths fail closed until authenticated session/dataplane evidence is wired. The receipt attests that JurisPath checked a path claim against a policy version, not that a payment is legally compliant.

## Features

- **Policy Engine** — YAML-based corridor policies with strict all-hop enforcement
- **Path-Policy Receipts** — Ed25519-signed receipts with top-level evidence class/proof status, monotonic sequence numbers, and append-only storage (BoltDB)
- **Violation Detection** — Real-time pub/sub alerting via Server-Sent Events with severity classification
- **Path Pre-filtering** — Filter caller-supplied SCION-style path candidates in demo mode; production SCION-observed path discovery remains future work
- **Replay Detection** — Prevents stale path reuse via sequence number and timestamp validation
- **Threshold Signing** — k-of-n multi-oracle signing support
- **Audit Log** — Append-only BoltDB-backed audit trail
- **DLT Consensus** — Lightweight 2-phase consensus engine (propose, vote, commit)
- **Dashboard** — Web UI with SVG topology visualization, real-time transaction flow, and violation alerts

## Corridor Policies

Three policies are included:

| Policy | Allowed ISDs | Mode | Use Case |
|---|---|---|---|
| `swiss_dlt.yaml` | ISD-CH | Strict | Domestic Swiss DLT settlement |
| `eu_settlement.yaml` | ISD-CH, ISD-EU | Strict | Cross-border CHF-EUR settlement |
| `demo_mixed.yaml` | ISD-CH, ISD-EU, ISD-X | Strict | Demo and testing |

Only **strict mode** is supported: every hop must stay within allowed ISDs.
Unsupported policy modes fail closed.

## Getting Started

### Prerequisites

- Go 1.24.2+
- Docker and Docker Compose (optional)

### TLS Startup Mode

JurisPath starts fail-closed by default:
- Set `JURISPATH_TLS_CERT` and `JURISPATH_TLS_KEY` to serve HTTPS.
- Set `JURISPATH_INSECURE=true` only for explicit local HTTP demo/dev mode.
- Set `JURISPATH_API_TOKEN` to protect `/api/*`, or set
  `JURISPATH_UNAUTHENTICATED_API=true` only for explicit local demo/dev mode.

See [docs/fail-closed-tls-startup.md](docs/fail-closed-tls-startup.md) for the full local and Docker workflows.

### Build and Run

```bash
make build
JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true ./bin/jurispath
```

The server starts on `:8080` by default.
- Local HTTP demo/dev mode: `make run`, then open `http://localhost:8080`
- Local HTTPS mode: `make tls-cert`, then `JURISPATH_TLS_CERT=deploy/certs/cert.pem JURISPATH_TLS_KEY=deploy/certs/key.pem JURISPATH_API_TOKEN=dev-token make run-tls`

### CLI

The `jurispath` binary also includes client commands for a running oracle:

```bash
./bin/jurispath --help
./bin/jurispath serve
./bin/jurispath settle --help
./bin/jurispath health
./bin/jurispath status
./bin/jurispath policies
./bin/jurispath check --policy chf-eur-settlement-v1 --path 1-ff00:0:110,2-ff00:0:210
./bin/jurispath settle --from CH --to EU --amount 100 --currency CHF --policy chf-eur-settlement-v1 --path 1-ff00:0:110,2-ff00:0:210
./bin/jurispath filter-paths --policy chf-eur-settlement-v1 --paths '1-ff00:0:110,2-ff00:0:210;1-ff00:0:110,3-ff00:0:310'
./bin/jurispath verify-chain
./bin/jurispath demo
```

Set `JURISPATH_CLI_BASE_URL` for non-default servers and
`JURISPATH_CLI_API_TOKEN` or `JURISPATH_API_TOKEN` for authenticated APIs.
Use `--output json` or `-o json` on list/status commands for script-friendly output.
Generate shell completion with `./bin/jurispath completion bash|zsh|fish`.

### Run Demo Scenarios

```bash
make demo
```

Runs four scenarios:
- **Scenario A** — Path-policy-allowed CHF-EUR demo settlement via ISD-CH and ISD-EU
- **Scenario B** — Corridor policy violation: settlement path transits unauthorized ISD-X
- **Scenario C** — Swiss-only settlement
- **Scenario D** — Path pre-filtering: only policy-allowed candidates returned

Demo receipts and violations expose `evidence_class` and `proof_status` at the
top level. The default local demo reports `explicit-demo` and `unverified` so
the PoC does not present caller-supplied path metadata as observed SCION
dataplane evidence.

For TLS demos against the local self-signed cert, start the HTTPS server and run:

```bash
make demo-tls
```

### PoC Metrics

The proposal metrics can be regenerated locally:

```bash
make poc-metrics
```

This reports path-check p50/p95 latency, signed receipt JSON size,
receipt-chain verification time, and fail-closed behavior for missing proof
material and receipt-store append failures. See
[docs/poc-metrics.md](docs/poc-metrics.md) for the latest local baseline.

### Docker

```bash
make up             # app-only PoC startup
make compose-smoke  # build/start app and verify health/policies/demo
make down           # stop
```

The default Docker target runs JurisPath in explicit-path demo mode and does
not require the experimental SCION topology. The packaged `validators.yaml`
uses loopback validator addresses for this single-process PoC flow.

For the optional 3-ISD SCION topology, generate crypto and enable the compose
profile:

```bash
make scion-image
make topo
make up-scion
```

To build the optional SCION profile, start all SCION services plus the app, and
wait for process health checks:

```bash
make compose-smoke-scion
```

The SCION image builds from SCION v0.14.0 Debian release assets for `amd64`
and `arm64`. `make scion-image` makes the bundled `scion-pki` available to
`make topo` when no local `scion-pki` is installed. Without either source,
`make topo` creates placeholder TRC files for layout inspection only; those
placeholders are not valid enough for SCION services to become healthy.
`make compose-smoke-scion` validates topology process startup, not
SCION-observed JurisPath evidence. Real SCION validator transport remains
experimental and requires deliberate `JURISPATH_SCION_MODE=true`
configuration.

For Docker TLS mode with local development certs:

```bash
make up-tls-local
```

### Tests

```bash
make test
```

## API Endpoints

`/api/*` endpoints require `Authorization: Bearer <JURISPATH_API_TOKEN>` by
default. Local demo targets set `JURISPATH_UNAUTHENTICATED_API=true` explicitly.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/check` | Check path metadata against a corridor policy |
| `POST` | `/api/settle` | Submit a DLT settlement transaction |
| `POST` | `/api/filter-paths` | Filter candidate paths to policy-allowed options |
| `GET` | `/api/receipts` | List all path-policy receipts |
| `GET` | `/api/violations` | List all recorded violations |
| `GET` | `/api/policies` | List loaded corridor policies |
| `GET` | `/api/ledger` | View ledger state |
| `GET` | `/api/transactions` | View transaction history |
| `GET` | `/api/events` | SSE stream for real-time violation alerts |
| `POST` | `/api/rotate-key` | Rotate the oracle signing key and archive the old key. Requires `X-JurisPath-Admin-Token`. |

### Settlement Atomicity

`POST /api/settle` treats a client-supplied `transaction_id` as an idempotency
key. The server stores a canonical digest of the original settlement request,
including amount, currency, policy, and the exact `raw_path` bytes. A retry with
the same request returns the original settlement receipt; a retry with different
settlement or path data returns `409 TX_CONFLICT`.

Ordinary settlement success requires both confirmed consensus and a durable
receipt. If consensus commits but receipt generation or persistence fails, the
API returns `500 SETTLEMENT_RECEIPT_FAILED` with `consensus.confirmed=true`,
`receipt_persisted=false`, and a persistence warning so the caller cannot
mistake a receipt-less settlement for normal success.

## Project Structure

```
cmd/
  jurispath/       Server entry point and CLI client
  demo/            Legacy standalone demo client
config/            Environment-based configuration
dashboard/         Web UI (HTML/CSS/JS)
deploy/            Docker Compose and SCION topology
internal/
  api/             HTTP API server and SSE streaming
  audit/           Append-only BoltDB audit log
  dlt/             Consensus engine and ledger state machine
  pathcheck/       ISD path-policy checker and path filter
  policy/          YAML policy loader
  receipt/         Ed25519 receipt signing and BoltDB store
  scion/           SCION path extraction and fingerprinting
  security/        Replay detection and threshold signing
  violation/       Violation detection, pub/sub, and BoltDB store
pkg/model/         Shared data types (ASHop, SCIONPath, Receipt, Violation)
policies/          Corridor policy YAML files
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `JURISPATH_LISTEN` | `:8080` | Server listen address |
| `JURISPATH_POLICY_DIR` | `policies` | Path to corridor policy YAML files |
| `JURISPATH_DASHBOARD_DIR` | `dashboard` | Path to dashboard static files |
| `JURISPATH_DATA_DIR` | `data/` | Directory for BoltDB receipt, violation, and audit stores |
| `JURISPATH_LOG_LEVEL` | `info` | Structured log level: `debug`, `info`, `warn`, or `error` |
| `JURISPATH_ORACLE_KEY` | `data/oracle.key` | Active oracle signing key path. `/api/rotate-key` archives this file before installing a new key. |
| `JURISPATH_TRC_DIR` | *(empty)* | Optional directory of signed `.trc` files for experimental ISD proof metadata. This does not make API-supplied paths SCION-observed. Empty uses explicit placeholder proofs for local/demo mode. |
| `JURISPATH_THRESHOLD_K` | *(empty)* | Optional receipt threshold-signing quorum. Must be set with `JURISPATH_THRESHOLD_N`. |
| `JURISPATH_THRESHOLD_N` | *(empty)* | Optional receipt threshold-signing group size. The current implementation generates in-memory threshold oracle keys at startup. |
| `JURISPATH_TLS_CERT` | *(empty)* | TLS certificate path. Must be set with `JURISPATH_TLS_KEY`. |
| `JURISPATH_TLS_KEY` | *(empty)* | TLS private key path. Must be set with `JURISPATH_TLS_CERT`. |
| `JURISPATH_INSECURE` | `false` | Explicitly allow plaintext HTTP startup for local demo/dev mode. |
| `JURISPATH_API_TOKEN` | *(empty)* | Bearer token required for `/api/*` endpoints. |
| `JURISPATH_ADMIN_TOKEN` | *(empty)* | Privileged token required in `X-JurisPath-Admin-Token` for `/api/rotate-key`. |
| `JURISPATH_UNAUTHENTICATED_API` | `false` | Explicitly allow unauthenticated API access for local demo/dev mode. |
| `JURISPATH_VALIDATORS` | `validators.yaml` | Path to validator topology and balance configuration |
| `JURISPATH_SCION_MODE` | `false` | Enable experimental SCION-mode startup and transport wiring. The current API settlement path remains demo-oriented; API-supplied `raw_path` is rejected until authenticated path evidence and real validator/session flow are wired. |
| `JURISPATH_SCION_DAEMON` | `127.0.0.1:30255` | SCION daemon address used in SCION mode |
| `JURISPATH_VALIDATOR_ID` | *(empty)* | Local validator ID, required when `JURISPATH_SCION_MODE=true` |
| `JURISPATH_CLI_BASE_URL` | `http://localhost:8080` | Base URL used by `cmd/jurispath` client commands. |
| `JURISPATH_CLI_API_TOKEN` | *(empty)* | Bearer token used by `cmd/jurispath` client commands; falls back to `JURISPATH_API_TOKEN`. |
| `JURISPATH_CLI_INSECURE_TLS` | `false` | Allow `cmd/jurispath` client commands to connect to local self-signed TLS certs. |
| `JURISPATH_DEMO_BASE_URL` | `http://localhost:8080` | Base URL used by `cmd/demo`. |
| `JURISPATH_DEMO_API_TOKEN` | *(empty)* | Bearer token used by `cmd/demo`; falls back to `JURISPATH_API_TOKEN`. |
| `JURISPATH_DEMO_INSECURE_TLS` | `false` | Allow `cmd/demo` to connect to local self-signed TLS certs. |

## References

- [SNB Working Paper 2025-15](https://www.snb.ch/en/publications/research/working-papers/2025/working_paper_2025_15) — SCION and cross-border payments: Enhancing security and compliance in DLT networks
- [SCION Architecture](https://www.scion-architecture.net/) — A secure Internet architecture
- [Secure Swiss Finance Network](https://www.six-group.com/en/products-services/banking-services/ssfn.html) — Production SCION deployment for Swiss finance
- [FINMA Circular 2023/1](https://www.finma.ch/) — Operational risks and resilience; in force since 1 January 2024, with transitional provisions for selected requirements

## License

Apache 2.0 — see [LICENSE](LICENSE).
