GO ?= go

.PHONY: all test integration lint fmt vet cover vuln tidy

all: fmt lint test

test:
	$(GO) test -race -count=1 ./...

integration:
	$(GO) test -race -count=1 -tags integration ./...

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

vet:
	$(GO) vet -tags integration ./...

cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out ./... && $(GO) tool cover -func=coverage.out | tail -1

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	$(GO) mod tidy
