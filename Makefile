# Ringtail - Post-Quantum Threshold Signature Scheme
# Makefile for building, testing, and managing the project

.PHONY: all build test clean fmt lint vet coverage bench run help install-tools

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet
GOLINT=golangci-lint

# Binary name
BINARY_NAME=ringtail
BINARY_PATH=./bin/$(BINARY_NAME)

# Test parameters
TEST_TIMEOUT=30s
BENCH_TIME=10s
COVERAGE_OUT=coverage.out
COVERAGE_HTML=coverage.html

# Build flags
LDFLAGS=-ldflags "-s -w"
BUILD_FLAGS=-v

# Default target
all: test build

## help: Display this help message
help:
	@echo "Ringtail - Post-Quantum Threshold Signature Scheme"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	$(GOBUILD) $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY_PATH) .
	@echo "Build complete: $(BINARY_PATH)"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -timeout $(TEST_TIMEOUT) ./...

## test-short: Run short tests only
test-short:
	@echo "Running short tests..."
	$(GOTEST) -v -short -timeout $(TEST_TIMEOUT) ./...

## test-race: Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	$(GOTEST) -v -race -timeout $(TEST_TIMEOUT) ./...

## coverage: Generate test coverage report
coverage:
	@echo "Generating coverage report..."
	$(GOTEST) -v -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"
	@echo "Coverage summary:"
	@$(GOCMD) tool cover -func=$(COVERAGE_OUT) | grep total | awk '{print "Total coverage: " $$3}'

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchtime=$(BENCH_TIME) -benchmem ./...

## bench-cpu: Run benchmarks with CPU profiling
bench-cpu:
	@echo "Running benchmarks with CPU profiling..."
	$(GOTEST) -bench=. -benchtime=$(BENCH_TIME) -benchmem -cpuprofile=cpu.prof ./...
	@echo "CPU profile saved to cpu.prof"
	@echo "View with: go tool pprof cpu.prof"

## bench-mem: Run benchmarks with memory profiling
bench-mem:
	@echo "Running benchmarks with memory profiling..."
	$(GOTEST) -bench=. -benchtime=$(BENCH_TIME) -benchmem -memprofile=mem.prof ./...
	@echo "Memory profile saved to mem.prof"
	@echo "View with: go tool pprof mem.prof"

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -w -s .
	@echo "Code formatting complete"

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed. Run 'make install-tools' to install it."; \
		exit 1; \
	fi

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## mod: Download and tidy Go modules
mod:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	@echo "Tidying modules..."
	$(GOMOD) tidy
	@echo "Verifying modules..."
	$(GOMOD) verify

## clean: Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	@rm -rf bin/
	@rm -f $(COVERAGE_OUT) $(COVERAGE_HTML)
	@rm -f *.prof
	@rm -f *.test
	@echo "Clean complete"

## install: Install the binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME) to $(GOPATH)/bin..."
	@cp $(BINARY_PATH) $(GOPATH)/bin/
	@echo "Installation complete"

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing goimports..."
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "Installing staticcheck..."
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "Tools installation complete"

## run: Run the application with default parameters
run: build
	@echo "Running $(BINARY_NAME)..."
	$(BINARY_PATH)

## run-local: Run local simulation
run-local: build
	@echo "Running local simulation..."
	$(BINARY_PATH) l 0 0

## run-party: Run as party (requires party ID, IP, and port)
run-party: build
	@if [ -z "$(PARTY_ID)" ] || [ -z "$(IP)" ] || [ -z "$(PORT)" ]; then \
		echo "Usage: make run-party PARTY_ID=1 IP=127.0.0.1 PORT=8000"; \
		exit 1; \
	fi
	@echo "Running as party $(PARTY_ID) on $(IP):$(PORT)..."
	$(BINARY_PATH) $(PARTY_ID) $(IP) $(PORT)

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t ringtail:latest .

## docker-run: Run Docker container
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -it ringtail:latest

## ci: Run CI pipeline locally (format, vet, lint, test, build)
ci: fmt vet lint test-race coverage build
	@echo "CI pipeline complete"

## check: Quick check (format, vet, test)
check: fmt vet test-short
	@echo "Quick check complete"

## update: Update dependencies to latest versions
update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy
	@echo "Dependencies updated"

## version: Display Go version and module info
version:
	@echo "Go version:"
	@$(GOCMD) version
	@echo ""
	@echo "Module info:"
	@$(GOCMD) list -m all | head -5

## stats: Display code statistics
stats:
	@echo "Code statistics:"
	@echo "  Lines of code:"
	@find . -name "*.go" -not -path "./vendor/*" | xargs wc -l | tail -1
	@echo "  Number of Go files:"
	@find . -name "*.go" -not -path "./vendor/*" | wc -l
	@echo "  Number of test files:"
	@find . -name "*_test.go" -not -path "./vendor/*" | wc -l

# Create necessary directories
init:
	@mkdir -p bin

.DEFAULT_GOAL := help