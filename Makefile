VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/esuEdu/wraith/internal/version.Version=$(VERSION)

.PHONY: build test vet spike-source spike-bypass

build:
	go build -ldflags "$(LDFLAGS)" -o wraith ./cmd/wraith

test:
	go test ./...

vet:
	go vet ./...

spike-source:
	go run ./spike/source

spike-bypass:
	@test -n "$(HOST)" || (echo "usage: make spike-bypass HOST=example.com [IFACE=en0]"; exit 2)
	go run ./spike/bypass -host $(HOST) -iface $${IFACE:-en0}
