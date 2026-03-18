.PHONY: build test test-unit test-integration lint generate clean deploy

BINARY := identity-server
MAIN   := ./cmd/server

build:
	go build -o bin/$(BINARY) $(MAIN)

# Unit tests only (no external deps — runs in CI without any setup)
test: test-unit

test-unit:
	go test -race -count=1 ./...

# Integration tests require a real filesystem for SQLite; no network deps (R2 is mocked)
test-integration:
	go test -race -count=1 -tags integration ./...

# Run all tests
test-all: test-unit test-integration

# Regenerate all mocks from interfaces
generate:
	go generate ./...

lint:
	go vet ./...

coverage:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/ coverage.out coverage.html

deploy:
	./deploy/deploy.sh sweeney@garibaldi
