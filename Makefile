.PHONY: help build test test-race vet lint docker-up docker-down docker-build clean

help: ## Display available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Compile GrantSupport binary
	go build -v -ldflags="-w -s" -o bin/grantsupport cmd/server/main.go

test: ## Run unit and integration tests
	go test -v -count=1 ./...

test-race: ## Run tests with Go race detector enabled
	go test -v -race -count=1 ./...

vet: ## Run Go static analysis
	go vet ./...

docker-build: ## Build Linux distroless Docker container image
	docker build -t grantsupport:latest .

docker-up: ## Start PostgreSQL, MySQL, MariaDB, and Valkey test infrastructure
	docker compose up -d

docker-down: ## Stop and remove all test infrastructure containers
	docker compose down -v

clean: ## Remove compiled binaries and test coverage output
	rm -rf bin/ coverage.html coverage.out profile.out
