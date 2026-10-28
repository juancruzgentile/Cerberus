# ==============================================================================
# Cerberus — Root Makefile (C11 + Go + Rust + SQLite WAL)
# ==============================================================================
# Targets:
#   make build   -> compila las 3 cabezas
#   make test    -> ejecuta TODAS las suites (schema, C, Go, Rust, E2E)
#   make e2e     -> suite End-to-End políglota + pruebas del lanzador
#   make clean   -> limpia artefactos compilados
# ==============================================================================

SHELL := /bin/bash
export PATH := $(HOME)/.local/bin:$(HOME)/.cargo/bin:$(PATH)

PYTHON ?= python3
GO     ?= go
CARGO  ?= cargo

INGESTOR_BIN := ingestor-c/bin/cerberus-ingestor
ALERTER_BIN  := alerter-go/bin/cerberus-alerter
SEARCH_BIN   := search-rust/target/release/cerberus-search

.PHONY: all build build-c build-go build-rust test test-schema test-c test-go test-rust e2e clean

all: build

build: build-c build-go build-rust

build-c:
	$(MAKE) -C ingestor-c

build-go:
	cd alerter-go && CGO_ENABLED=0 $(GO) build -trimpath -o bin/cerberus-alerter ./cmd/alerter

build-rust:
	cd search-rust && $(CARGO) build --release

test: test-schema test-c test-go test-rust e2e
	@echo "=============================================================================="
	@echo " Cerberus: todas las suites aprobadas (schema, C11, Go, Rust, E2E)"
	@echo "=============================================================================="

test-schema:
	$(PYTHON) schema/test_schema.py
	$(PYTHON) schema/test_security_schema.py

test-c:
	$(MAKE) -C ingestor-c test

test-go:
	cd alerter-go && $(GO) vet ./... && $(GO) test -count=1 ./...

test-rust:
	cd search-rust && RUSTFLAGS="-D warnings" $(CARGO) test

e2e: build
	$(PYTHON) tests/test_e2e_cerberus.py
	$(PYTHON) tests/test_launcher.py

clean:
	$(MAKE) -C ingestor-c clean
	rm -rf alerter-go/bin
	cd search-rust && $(CARGO) clean
