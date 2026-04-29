# Fail-Closed TLS Startup

JurisPath requires HTTPS by default. Plaintext HTTP starts only when
`JURISPATH_INSECURE=true` is set explicitly.

## Local HTTP Demo Mode

```bash
make run
make demo
```

`make run` and `make demo` set `JURISPATH_INSECURE=true` for local development.

## Local HTTPS Mode

```bash
make tls-cert
JURISPATH_TLS_CERT=deploy/certs/cert.pem \
JURISPATH_TLS_KEY=deploy/certs/key.pem \
make run-tls
```

The generated certificate is self-signed and includes SANs for `localhost` and
`127.0.0.1`.

In another terminal, run:

```bash
make demo-tls
```

`make demo-tls` sets `JURISPATH_DEMO_INSECURE_TLS=true` so the demo client can
connect to the local self-signed certificate. Do not use that setting outside
local development.

## Docker Compose

HTTP demo mode:

```bash
make up
```

TLS mode with local development certs:

```bash
make up-tls-local
```

Manual TLS mode:

```bash
JURISPATH_TLS_CERT=/certs/cert.pem \
JURISPATH_TLS_KEY=/certs/key.pem \
make up-tls
```

`make up-tls` fails fast if either TLS path is missing. Compose mounts
`${JURISPATH_CERTS_DIR:-./certs}` to `/certs`.

## Validation

```bash
make docs-check-tls
go test ./cmd/demo ./config
```
