VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/esuEdu/wraith/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: build build-universal test lint fmt-check vet golangci forbidden rules-check \
        spike-source spike-bypass clean

## build: binary for this Mac, at ./wraith
build:
	go build -ldflags "$(LDFLAGS)" -o wraith ./cmd/wraith

## build-universal: arm64 + amd64 binary at dist/wraith (R7.1)
build-universal:
	mkdir -p dist
	CGO_ENABLED=1 GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/wraith-arm64 ./cmd/wraith
	CGO_ENABLED=1 GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/wraith-amd64 ./cmd/wraith
	lipo -create -output dist/wraith dist/wraith-arm64 dist/wraith-amd64
	rm dist/wraith-arm64 dist/wraith-amd64

## test: unit, integration and macOS system tests, with the race detector
test:
	go test -race -coverprofile=coverage.out ./...

## lint: everything the CI lint job runs
lint: fmt-check vet golangci forbidden rules-check

fmt-check:
	@out="$$(gofmt -l . | grep -v '^spike/' || true)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

golangci:
	@command -v golangci-lint >/dev/null || \
	  (echo "golangci-lint not found: brew install golangci-lint (CI uses $(GOLANGCI_LINT_VERSION))"; exit 1)
	golangci-lint run

forbidden:
	./scripts/forbidden.sh

rules-check:
	go run ./tools/rulescheck

spike-source:
	go run ./spike/source

spike-bypass:
	@test -n "$(HOST)" || (echo "usage: make spike-bypass HOST=example.com [IFACE=en0]"; exit 2)
	go run ./spike/bypass -host $(HOST) -iface $${IFACE:-en0}

clean:
	rm -rf wraith dist coverage.out
