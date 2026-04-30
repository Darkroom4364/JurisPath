.PHONY: help build test lint run run-tls demo demo-tls tls-cert docs-check-tls up up-tls up-tls-local down topo clean

GO := go

help:
	@echo "JurisPath dev targets"
	@echo "  make run          - local HTTP startup (sets JURISPATH_INSECURE=true)"
	@echo "  make run-tls      - local HTTPS startup (requires JURISPATH_TLS_CERT and JURISPATH_TLS_KEY)"
	@echo "  make demo         - start local HTTP server and run demo scenarios"
	@echo "  make demo-tls     - run demo scenarios against https://localhost:8080"
	@echo "  make tls-cert     - generate local self-signed certs in deploy/certs"
	@echo "  make docs-check-tls - verify TLS workflow docs stay aligned"
	@echo "  make up           - docker compose HTTP demo startup (insecure=true)"
	@echo "  make up-tls       - docker compose TLS startup (requires JURISPATH_TLS_CERT and JURISPATH_TLS_KEY)"
	@echo "  make up-tls-local - generate local certs and start compose TLS mode"
	@echo "  make down         - stop docker compose stack"

build:
	$(GO) build -o bin/jurispath ./cmd/jurispath

test:
	$(GO) test ./... -v

lint:
	golangci-lint run

run: build
	JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true ./bin/jurispath

check-tls-env:
	@test -n "$(JURISPATH_TLS_CERT)" || (echo "JURISPATH_TLS_CERT is required for TLS startup targets"; exit 1)
	@test -n "$(JURISPATH_TLS_KEY)" || (echo "JURISPATH_TLS_KEY is required for TLS startup targets"; exit 1)

run-tls: check-tls-env build
	JURISPATH_TLS_CERT="$(JURISPATH_TLS_CERT)" JURISPATH_TLS_KEY="$(JURISPATH_TLS_KEY)" ./bin/jurispath

demo: build
	@echo "Starting JurisPath server..."
	@sh -c 'JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true ./bin/jurispath serve & pid=$$!; trap "kill $$pid 2>/dev/null || true" EXIT; sleep 1; echo "Running demo scenarios..."; ./bin/jurispath demo'

demo-tls: build
	JURISPATH_CLI_BASE_URL=https://localhost:8080 JURISPATH_CLI_INSECURE_TLS=true ./bin/jurispath demo

tls-cert:
	mkdir -p deploy/certs
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		-keyout deploy/certs/key.pem \
		-out deploy/certs/cert.pem

docs-check-tls:
	rg -n "make run-tls|make up-tls-local|make demo-tls|make tls-cert|JURISPATH_INSECURE" README.md docs/fail-closed-tls-startup.md

topo:
	deploy/scripts/gen-topo.sh

up:
	JURISPATH_INSECURE=true JURISPATH_UNAUTHENTICATED_API=true docker compose -f deploy/docker-compose.yml up --build

up-tls: check-tls-env
	JURISPATH_INSECURE=false docker compose -f deploy/docker-compose.yml up --build

up-tls-local: tls-cert
	JURISPATH_TLS_CERT=/certs/cert.pem JURISPATH_TLS_KEY=/certs/key.pem $(MAKE) up-tls

down:
	docker compose -f deploy/docker-compose.yml down

clean:
	rm -rf bin/
