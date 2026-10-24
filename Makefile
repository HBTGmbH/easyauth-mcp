BINARY := bin/easyauth-mcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test cover fmt fmt-check vet lint check tidy clean run

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/easyauth-mcp

test:
	go test ./...

cover:
	go test -coverprofile=coverage.txt ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

# Needs golangci-lint (https://golangci-lint.run), configured in .golangci.yml.
lint:
	golangci-lint run ./...

check: fmt-check vet test

tidy:
	go mod tidy

clean:
	rm -rf bin coverage.txt

run: build
	./$(BINARY) --help
