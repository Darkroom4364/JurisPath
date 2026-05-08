# JurisPath PoC Metrics

Baseline captured on 2026-05-08 with:

```bash
make poc-metrics
```

Environment:
- Host: macOS arm64 development machine
- Toolchain used for baseline: `go1.26.2 darwin/arm64`
- Module requirement: Go 1.24.2+
- Evidence class: `explicit-demo`
- Proof status: `unverified`

Results:

| Metric | Value |
|---|---:|
| Path-check samples | 1000 |
| Path-check p50 | 125ns |
| Path-check p95 | 209ns |
| Signed receipt JSON size | 1472 bytes |
| Receipt-chain length | 1000 receipts |
| Receipt-chain verification time | 41.907166ms |
| Missing proof material behavior | fail-closed |
| Receipt-store append failure behavior | fail-closed |

These numbers are local demo measurements, not production SCION dataplane
benchmarks. Re-run `make poc-metrics` on the target demo machine before using
the values in a live presentation.
