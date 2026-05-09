# JurisPath Documentation

This directory contains the judge-facing and handoff documentation for the
JurisPath hackathon proof of concept.

## Start Here

- [Demo script](demo-script.md): 4-5 minute walkthrough for judges.
- [Project status](project-status.md): current verification record, demo-ready
  scope, and production boundary.
- [PoC metrics](poc-metrics.md): latest local timing and receipt-size baseline.

## Supporting Docs

- [Fail-closed TLS startup](fail-closed-tls-startup.md): local and Docker TLS
  startup modes.
- [Architecture diagram](architecture-diagram.html): visual explanation of the
  path-policy receipt loop and current evidence boundary.

## Boundary

The current PoC emits `explicit-demo` / `unverified` evidence. It demonstrates
the policy decision, receipt, violation, audit, dashboard, CLI, API, metrics,
and Docker flows. It does not yet produce `scion-observed` receipt evidence
from authenticated SCION dataplane/session material.
