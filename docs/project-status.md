# JurisPath Project Status

Status date: 2026-05-08.

JurisPath is complete as a hackathon proof of concept. The implemented artifact
shows the full path-policy receipt loop: strict corridor policy checks, accepted
settlements with signed receipts, blocked settlements with structured
violations, path pre-filtering, receipt-chain verification, metrics, CLI/API
surfaces, dashboard visibility, and Docker smoke tests.

## Verified

The following checks passed on the local development machine:

```bash
go test ./... -count=1
go vet ./...
make poc-metrics
make docs-check-tls
git diff --check
docker compose -f deploy/docker-compose.yml config
docker compose -f deploy/docker-compose.yml --profile scion-topology config
make compose-smoke
make compose-smoke-scion
```

`make compose-smoke-scion` verifies that the optional five-container SCION
topology starts healthy with SCION v0.14.0 process health checks. It does not
claim that JurisPath receipts are generated from observed SCION dataplane
evidence.

## Demo-Ready Scope

- `make demo` runs the judge-facing local flow.
- `docs/demo-script.md` provides a 4-5 minute walkthrough.
- `make poc-metrics` regenerates local PoC metrics.
- `make compose-smoke` validates the app-only Docker path.
- `make compose-smoke-scion` validates optional SCION process startup only; it
  does not produce `scion-observed` receipt evidence.

## Boundary

Current receipts use `evidence_class=explicit-demo` and
`proof_status=unverified`. This is intentional for the PoC: caller-supplied path
metadata is useful for demonstrating policy semantics, receipts, violations, and
auditability, but it is not proof that packets traversed that path.

The next production milestone is an authenticated `scion-observed` evidence
adapter that derives path evidence from SCION session or daemon metadata, raw
dataplane path bytes, hop MAC material, and CP-PKI/TRC-rooted proof material.

## Production Work Remaining

- Authenticated SCION evidence adapter.
- TRC/CP-PKI proof capture and verification in receipts.
- Settlement-gateway or validator-networking integration near transmission
  time.
- External log anchoring or independent receipt-log replication.
- Production key management, monitoring, incident handling, and policy
  governance.
