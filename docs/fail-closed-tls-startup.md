# Fail-Closed TLS Startup

JurisPath requires HTTPS by default. Plaintext HTTP starts only when
`JURISPATH_INSECURE=true` is set explicitly. API endpoints also require a
bearer token by default; set `JURISPATH_API_TOKEN`, or use
`JURISPATH_UNAUTHENTICATED_API=true` only for local demo mode.

## Local HTTP Demo Mode

```bash
make run
make demo
```

`make run` and `make demo` set `JURISPATH_INSECURE=true` and
`JURISPATH_UNAUTHENTICATED_API=true` for local development.

## Local HTTPS Mode

```bash
make tls-cert
JURISPATH_TLS_CERT=deploy/certs/cert.pem \
JURISPATH_TLS_KEY=deploy/certs/key.pem \
JURISPATH_API_TOKEN=dev-token \
make run-tls
```

The generated certificate is self-signed and includes SANs for `localhost` and
`127.0.0.1`.

In another terminal, run:

```bash
make demo-tls
```

`make demo-tls` sets `JURISPATH_DEMO_INSECURE_TLS=true` so the demo client can
connect to the local self-signed certificate. If the server has API auth enabled,
set `JURISPATH_DEMO_API_TOKEN` or reuse `JURISPATH_API_TOKEN` for the demo
client. Do not use insecure TLS outside local development.

## Docker Compose

HTTP demo mode:

```bash
make up
```

TLS mode with local development certs:

```bash
JURISPATH_API_TOKEN=dev-token \
make up-tls-local
```

Manual TLS mode:

```bash
JURISPATH_TLS_CERT=/certs/cert.pem \
JURISPATH_TLS_KEY=/certs/key.pem \
JURISPATH_API_TOKEN=dev-token \
make up-tls
```

`make up-tls` fails fast if either TLS path is missing or API authentication is
not configured. Compose mounts `${JURISPATH_CERTS_DIR:-./certs}` to `/certs`.

## Validation

```bash
make docs-check-tls
go test ./cmd/demo ./config ./internal/api
```
