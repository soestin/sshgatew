.PHONY: build test check

VERSION ?= dev

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o sshgatew ./cmd/sshgatew

test:
	go test ./...

check:
	go test -race ./...
	go vet ./...
	govulncheck ./...
