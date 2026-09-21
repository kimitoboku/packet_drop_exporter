SHELL := /bin/sh

BIN := bin/packet-drop-exporter

.PHONY: all generate test race vet benchmark build licenses docker-test docker-build docker-integration docker-integration-test docker-soak fmt

all: test build

generate:
	go generate ./internal/bpf

test: generate
	go test ./...

race: generate
	go test -race ./...

vet: generate
	go vet ./...

benchmark: generate
	go test -run '^$$' -bench BenchmarkBuildSnapshot8192Entries -benchmem ./internal/collector

build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/packet-drop-exporter

licenses:
	go run ./cmd/license-bundle

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

docker-test:
	docker compose run --rm test

docker-build:
	docker compose build exporter

docker-integration:
	docker compose --profile integration up --build exporter

docker-integration-test:
	docker compose --profile integration-test run --build --rm integration-test

docker-soak:
	docker compose --profile integration --profile soak up --build --abort-on-container-exit --exit-code-from soak-probe exporter soak-probe
