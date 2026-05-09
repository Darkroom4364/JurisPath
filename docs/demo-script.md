# JurisPath Short Demo Script

Timebox: 4-5 minutes.

## Setup

Terminal 1:

```bash
make build
export JURISPATH_DATA_DIR="$(mktemp -d)"
JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true ./bin/jurispath serve
```

Open the dashboard at `http://localhost:8080`.

Terminal 2:

```bash
./bin/jurispath demo
```

## Talk Track

1. JurisPath answers one narrow PoC question: can a settlement gateway produce an auditable receipt that caller-supplied SCION-style path metadata was checked against a corridor policy before the demo settlement flow accepts it?

2. Scenario A is the happy path. Point out the CHF-EUR settlement path through ISD-CH and ISD-EU, the accepted settlement, the signed receipt, the path fingerprint, the sequence number, and the receipt-chain link.

3. Point out `evidence_class=explicit-demo` and `proof_status=unverified`. This is intentional: the demo demonstrates the receipt loop and policy engine, not observed dataplane traversal.

4. Scenario B is the control. The same corridor goes through ISD-X, so the settlement is blocked before commit. Point out the offending hop and the stored violation.

5. Scenario D shows operator ergonomics: path pre-filtering separates compliant candidates from rejected ones before sending.

## Inspect Evidence

```bash
./bin/jurispath receipts
./bin/jurispath violations
./bin/jurispath verify-chain
make poc-metrics
```

Say: the receipt chain verifies, violations are persisted, and the local PoC metrics cover path-check latency, receipt size, chain verification time, and fail-closed behavior.

## Close

JurisPath is demo-ready as a hackathon PoC: policy, receipt, violation, audit, CLI, API, dashboard, metrics, and Docker app smoke all work. The optional SCION profile is process-startup smoke only; the production milestone is the authenticated SCION evidence adapter that upgrades receipts from `explicit-demo` to `scion-observed`.

## Backup Commands

Fast terminal-only demo:

```bash
make demo
```

Docker app smoke:

```bash
make compose-smoke
```

Optional SCION process smoke:

```bash
make compose-smoke-scion
```
