.PHONY: build test lint run demo up down topo clean

GO := go

build:
	$(GO) build -o bin/jurispath ./cmd/jurispath
	$(GO) build -o bin/demo ./cmd/demo

test:
	$(GO) test ./... -v

lint:
	golangci-lint run

run: build
	./bin/jurispath

demo: build
	@echo "Starting JurisPath server..."
	./bin/jurispath &
	@sleep 1
	@echo "Running demo scenarios..."
	./bin/demo
	@kill %1 2>/dev/null || true

topo:
	deploy/scripts/gen-topo.sh

up:
	docker compose -f deploy/docker-compose.yml up --build

down:
	docker compose -f deploy/docker-compose.yml down

clean:
	rm -rf bin/
