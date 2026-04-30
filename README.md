# JurisPath

Jurisdiction-aware compliance oracle that validates SCION network paths against regulatory policies for cross-border DLT settlement. Issues signed compliance receipts, detects violations in real-time, and provides a live dashboard.

Implements the compliance architecture proposed in [SNB Working Paper 2025-15](https://www.snb.ch/en/publications/research/working-papers/2025/working_paper_2025_15), targeting the [Secure Swiss Finance Network (SSFN)](https://www.six-group.com/en/products-services/banking-services/ssfn.html).

## Architecture

```
Client Request (HTTP POST /api/check)
        |
    API Server
        |
  Path Extractor ── extracts AS hops, computes SHA-256 fingerprint
        |
  Path Compliance Checker ── validates path against jurisdiction policy
        |
   +----+----+
   |         |
Compliant  Violation
   |         |
Receipt    Violation Detector
Generator  (real-time SSE alerts)
   |
Ed25519-signed
Compliance Receipt
```

The oracle sits between DLT validators and the SCION network layer. It inspects path metadata on consensus messages, confirms all hops remain within authorized ISDs, and produces cryptographic compliance receipts or raises violation alerts.

## Features

- **Policy Engine** — YAML-based jurisdiction policies with strict and relaxed enforcement modes
- **Compliance Receipts** — Ed25519-signed receipts with monotonic sequence numbers and append-only storage (BoltDB)
- **Violation Detection** — Real-time pub/sub alerting via Server-Sent Events with severity classification
- **Path Pre-filtering** — Filter available SCION paths to only jurisdiction-compliant options before sending
- **Replay Detection** — Prevents stale path reuse via sequence number and timestamp validation
- **Threshold Signing** — k-of-n multi-oracle signing support
- **Audit Log** — Append-only BoltDB-backed audit trail
- **DLT Consensus** — Lightweight 2-phase consensus engine (propose, vote, commit)
- **Dashboard** — Web UI with SVG topology visualization, real-time transaction flow, and violation alerts

## Jurisdiction Policies

Three policies are included:

| Policy | Allowed ISDs | Mode | Use Case |
|---|---|---|---|
| `swiss_dlt.yaml` | ISD-CH | Strict | Domestic Swiss DLT settlement |
| `eu_settlement.yaml` | ISD-CH, ISD-EU | Strict | Cross-border CHF-EUR settlement |
| `demo_mixed.yaml` | ISD-CH, ISD-EU, ISD-X | Strict | Demo and testing |

**Strict mode** requires every hop to stay within allowed ISDs. **Relaxed mode** only checks entry and exit hops.

## Getting Started

### Prerequisites

- Go 1.22+
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
./bin/jurispath health
./bin/jurispath check --policy chf-eur-settlement-v1 --path 1-ff00:0:110,2-ff00:0:210
./bin/jurispath settle --from CH --to EU --amount 100 --currency CHF --policy chf-eur-settlement-v1 --path 1-ff00:0:110,2-ff00:0:210
./bin/jurispath filter-paths --policy chf-eur-settlement-v1 --paths '1-ff00:0:110,2-ff00:0:210;1-ff00:0:110,3-ff00:0:310'
./bin/jurispath verify-chain
./bin/jurispath demo
```

Set `JURISPATH_CLI_BASE_URL` for non-default servers and
`JURISPATH_CLI_API_TOKEN` or `JURISPATH_API_TOKEN` for authenticated APIs.

### Run Demo Scenarios

```bash
make demo
```

Runs three scenarios:
- **Scenario A** — Compliant CHF-EUR settlement via ISD-CH and ISD-EU
- **Scenario B** — Violation: settlement path transits unauthorized ISD-X
- **Scenario C** — Path pre-filtering: only compliant paths returned

For TLS demos against the local self-signed cert, start the HTTPS server and run:

```bash
make demo-tls
```

### Docker

```bash
make up      # start
make down    # stop
```

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
| `POST` | `/api/check` | Check path compliance against a policy |
| `POST` | `/api/settle` | Submit a DLT settlement transaction |
| `POST` | `/api/filter-paths` | Filter paths to compliant-only options |
| `GET` | `/api/receipts` | List all compliance receipts |
| `GET` | `/api/violations` | List all recorded violations |
| `GET` | `/api/policies` | List loaded jurisdiction policies |
| `GET` | `/api/ledger` | View ledger state |
| `GET` | `/api/transactions` | View transaction history |
| `GET` | `/api/events` | SSE stream for real-time violation alerts |
| `POST` | `/api/rotate-key` | Rotate the oracle signing key and archive the old key. Requires `X-JurisPath-Admin-Token`. |

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
  pathcheck/       ISD policy compliance checker and path filter
  policy/          YAML policy loader
  receipt/         Ed25519 receipt signing and BoltDB store
  scion/           SCION path extraction and fingerprinting
  security/        Replay detection and threshold signing
  violation/       Violation detection, pub/sub, and BoltDB store
pkg/model/         Shared data types (ASHop, SCIONPath, Receipt, Violation)
policies/          Jurisdiction policy YAML files
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `JURISPATH_LISTEN` | `:8080` | Server listen address |
| `JURISPATH_POLICY_DIR` | `policies` | Path to jurisdiction policy YAML files |
| `JURISPATH_DASHBOARD_DIR` | `dashboard` | Path to dashboard static files |
| `JURISPATH_ORACLE_KEY` | `data/oracle.key` | Active oracle signing key path. `/api/rotate-key` archives this file before installing a new key. |
| `JURISPATH_TRC_DIR` | *(empty)* | Optional directory of signed `.trc` files used to populate verified receipt ISD proof material. Empty uses explicit placeholder proofs for local/demo mode. |
| `JURISPATH_THRESHOLD_K` | *(empty)* | Optional receipt threshold-signing quorum. Must be set with `JURISPATH_THRESHOLD_N`. |
| `JURISPATH_THRESHOLD_N` | *(empty)* | Optional receipt threshold-signing group size. The current implementation generates in-memory threshold oracle keys at startup. |
| `JURISPATH_TLS_CERT` | *(empty)* | TLS certificate path. Must be set with `JURISPATH_TLS_KEY`. |
| `JURISPATH_TLS_KEY` | *(empty)* | TLS private key path. Must be set with `JURISPATH_TLS_CERT`. |
| `JURISPATH_INSECURE` | `false` | Explicitly allow plaintext HTTP startup for local demo/dev mode. |
| `JURISPATH_API_TOKEN` | *(empty)* | Bearer token required for `/api/*` endpoints. |
| `JURISPATH_ADMIN_TOKEN` | *(empty)* | Privileged token required in `X-JurisPath-Admin-Token` for `/api/rotate-key`. |
| `JURISPATH_UNAUTHENTICATED_API` | `false` | Explicitly allow unauthenticated API access for local demo/dev mode. |
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
- [FINMA Circular 2023/1](https://www.finma.ch/) — Operational risks and resilience requirements (compliance deadline: January 2026)

## License

Apache 2.0 — see [LICENSE](LICENSE).
