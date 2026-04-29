# JurisPath Agent Execution Policy

Date: 2026-04-29

This project uses a flat Paperclip team with explicit review gates. Agents may work
in parallel, but shared `main` is integration-only.

## Operating Model

- The human/board owns priorities, risky decisions, and merge approval.
- Tessa owns sprint coordination, issue dependencies, PR splits, and integration.
- Specialist agents own one active issue at a time.
- Quinn reviews tests and behavior before merge.
- Sable reviews security-sensitive changes before merge.
- Mira reviews paper-alignment claims and research notes.

The hierarchy is intentionally shallow. Tessa is an integration gate, not a
command bottleneck.

## Execution Rules

- Agents must not work directly on shared `main` except for explicitly approved
  coordination-only changes.
- Each active issue must declare owned files before implementation starts.
- An agent may own only one active implementation issue at a time unless Tessa
  explicitly grants an exception.
- Product code, docs, and coordination artifacts should not be mixed in one PR.
- Generated data and runtime state must not be committed unless the issue
  explicitly asks for fixtures.
- If an agent discovers a needed cross-scope change, it should stop and comment
  rather than expanding the issue silently.

Initial rollout exception: this policy takes effect after the introducing PR
merges, so subsequent PRs must enforce the separation rules above.

## Review Gates

Changes require review before merge when they touch:

- `cmd/jurispath`
- `internal/api`
- `internal/scion`
- `internal/dlt`
- `config`
- TLS/startup/security behavior
- receipt persistence or audit semantics
- consensus or settlement behavior

Security-sensitive changes require Sable review. API and behavior changes require
Quinn review. Integration splits require Tessa approval.

## Current Stash Split Map

The mixed agent output was preserved as:

```text
stash@{0}: On main: paperclip-mixed-agent-output-before-split
```

Recommended PR buckets:

1. HTTP listener timeout hardening.
2. Receipt persistence failure audit events.
3. SCION API path envelope and DLT path extraction.
4. TLS fail-closed docs and dev workflow.
5. Demo client settlement smoke flow.
6. Coordination and Paperclip helper artifacts.

Known tangled files that require hunk-level splitting:

- `Makefile`
- `README.md`
- `cmd/jurispath/main.go`
- `internal/api/server.go`
- `internal/api/server_test.go`

Known items to park or exclude from product PRs:

- `.togi-cache/`
- `data/`
- `jurispath`
- `togi.toml`
- `docs/coordination/.paperclip-api-state`
