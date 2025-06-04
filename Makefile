# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

# Prerequisites:
# - For VSOCK (AWS Nitro): rustup target add x86_64-unknown-linux-musl
# - For SGX: Intel SGX SDK installed + rustup target add x86_64-fortanix-unknown-sgx
# - Protocol Buffers compiler: apt-get install protobuf-compiler

ARCH=$(shell uname -m)
ifeq ($(ARCH), x86_64)
	VSOCK_TARGET=x86_64-unknown-linux-musl
else ifeq ($(ARCH), arm64)
	VSOCK_TARGET=aarch64-unknown-linux-musl
else
	$(error Unsupported architecture: $(ARCH))
endif

SGX_TARGET=x86_64-fortanix-unknown-sgx
SGX_SDK_PATH?=/opt/intel/sgxsdk
SGX_MODE?=HW

# Check if SGX SDK is available
SGX_AVAILABLE := $(shell test -d $(SGX_SDK_PATH) && echo 1 || echo 0)

.PHONY: help all tcp vsock sgx check test clean install deps security audit sbom dev-security pre-commit setup format lint

# Default target
all: tcp

help:
	@echo "Secure Sign Service - Build System"
	@echo "=================================="
	@echo ""
	@echo "🚀 Getting Started:"
	@echo "  setup    - Set up development environment"
	@echo "  check    - Run cargo check on all modules"
	@echo "  test     - Run tests"
	@echo ""
	@echo "🔨 Build Targets:"
	@echo "  tcp      - Build TCP server (secure-sign-tcp)"
	@echo "  vsock    - Build VSOCK server (secure-sign-vsock)"
	@echo "  sgx      - Build SGX enclave version (secure-sign-sgx)"
	@echo "  all      - Build all available targets"
	@echo ""
	@echo "🔒 Security & Quality:"
	@echo "  security - Run comprehensive security audit"
	@echo "  audit    - Run dependency security audit"
	@echo "  sbom     - Generate Software Bill of Materials"
	@echo "  format   - Format all code"
	@echo "  lint     - Run advanced linting"
	@echo ""
	@echo "🛠️  Maintenance:"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install binaries to /usr/local/bin"
	@echo "  deps     - Install build dependencies"
	@echo ""
	@echo "Environment Variables:"
	@echo "  SGX_SDK_PATH - Path to Intel SGX SDK (default: /opt/intel/sgxsdk)"
	@echo "  SGX_MODE     - SGX mode: HW or SW (default: HW)"

# Build TCP server
tcp:
	@echo "Building TCP server..."
	cargo build --release --features tcp --no-default-features
	cp target/release/secure-sign target/secure-sign-tcp
	@echo "TCP server built: target/secure-sign-tcp"

# Build VSOCK server  
vsock:
	@echo "Building VSOCK server..."
	@echo "Target architecture: $(VSOCK_TARGET)"
	cargo build --release --target=$(VSOCK_TARGET) --features vsock --no-default-features
	cp target/$(VSOCK_TARGET)/release/secure-sign target/secure-sign-vsock
	@echo "VSOCK server built: target/secure-sign-vsock"

# Build SGX version
sgx:
ifeq ($(SGX_AVAILABLE), 1)
	@echo "Building SGX enclave version..."
	@echo "SGX SDK Path: $(SGX_SDK_PATH)"
	@echo "SGX Mode: $(SGX_MODE)"
	
	# Build the enclave first
	cd secure-sign-sgx-enclave && \
		source $(SGX_SDK_PATH)/environment && \
		SGX_MODE=$(SGX_MODE) make
	
	# Build the SGX host application
	cd secure-sign-sgx && \
		source $(SGX_SDK_PATH)/environment && \
		SGX_MODE=$(SGX_MODE) cargo build --release
	
	cp secure-sign-sgx/target/release/secure-sign-sgx target/secure-sign-sgx
	@echo "SGX version built: target/secure-sign-sgx"
else
	@echo "Error: Intel SGX SDK not found at $(SGX_SDK_PATH)"
	@echo "Please install Intel SGX SDK or set SGX_SDK_PATH"
	@exit 1
endif

# Build all available targets
all-targets: tcp vsock
ifeq ($(SGX_AVAILABLE), 1)
	$(MAKE) sgx
endif

# Development targets
check:
	@echo "Running cargo check..."
	cargo check --all-targets --features tcp --no-default-features
	cargo check --all-targets --features vsock --no-default-features
	@echo "Checking individual modules..."
	cargo check -p secure-sign-core --all-features
	cargo check -p secure-sign-rpc --all-features  
	cargo check -p secure-sign-nitro --all-features
ifeq ($(SGX_AVAILABLE), 1)
	cd secure-sign-sgx && cargo check --all-features
	cd secure-sign-sgx-enclave && cargo check --all-features
endif

test:
	@echo "Running tests..."
	cargo test --all --features tcp --no-default-features
	cargo test --all --features vsock --no-default-features

# Utility targets
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f target/secure-sign-tcp target/secure-sign-vsock target/secure-sign-sgx
ifeq ($(SGX_AVAILABLE), 1)
	cd secure-sign-sgx-enclave && make clean
	cd secure-sign-sgx && cargo clean
endif
	@echo "Clean complete"

# Install dependencies
deps:
	@echo "Installing build dependencies..."
	@echo "Checking for protobuf compiler..."
	@which protoc > /dev/null || (echo "Installing protobuf-compiler..." && sudo apt-get update && sudo apt-get install -y protobuf-compiler)
	
	@echo "Adding Rust targets..."
	rustup target add $(VSOCK_TARGET)
	
ifeq ($(SGX_AVAILABLE), 1)
	rustup target add $(SGX_TARGET)
endif
	
	@echo "Dependencies installed"

# Install binaries
install: tcp
	@echo "Installing binaries to /usr/local/bin..."
	sudo cp target/secure-sign-tcp /usr/local/bin/secure-sign-tcp
	sudo chmod +x /usr/local/bin/secure-sign-tcp
	@echo "Installation complete"

# Development helpers
dev-tcp:
	cargo run --features tcp --no-default-features -- --help

dev-check:
	cargo fmt --all
	cargo clippy --all-targets --all-features

# SGX development helpers
sgx-sim:
	SGX_MODE=SW $(MAKE) sgx

sgx-hw:
	SGX_MODE=HW $(MAKE) sgx

# Print build information
info:
	@echo "Build Environment Information:"
	@echo "  Architecture: $(ARCH)"
	@echo "  VSOCK Target: $(VSOCK_TARGET)"
	@echo "  SGX SDK Path: $(SGX_SDK_PATH)"
	@echo "  SGX Available: $(SGX_AVAILABLE)"
	@echo "  SGX Mode: $(SGX_MODE)"
	@echo ""
	@rustc --version
	@cargo --version

# Security and audit targets
security:
	@echo "Running comprehensive security audit..."
	./scripts/security-audit.sh

audit:
	@echo "Running dependency security audit..."
	@command -v cargo-audit >/dev/null || cargo install cargo-audit
	cargo audit

sbom:
	@echo "Generating Software Bill of Materials..."
	@command -v cargo-cyclonedx >/dev/null || cargo install cargo-cyclonedx
	cargo cyclonedx --format json --output-file sbom.json
	@echo "SBOM generated: sbom.json"

# Enhanced development targets with security
dev-security:
	$(MAKE) audit
	cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used
	cargo fmt --all -- --check

# Pre-commit checks (recommended before committing)
pre-commit: dev-security test
	@echo "✅ Pre-commit checks complete"

# Setup development environment
setup:
	@echo "Setting up development environment..."
	./scripts/setup-environment.sh

# Code formatting
format:
	@echo "Formatting all Rust code..."
	cargo fmt --all
	@echo "✅ Code formatting complete"

# Advanced linting
lint:
	@echo "Running advanced linting..."
	cargo clippy --all-targets --features tcp --no-default-features -- -D warnings -A clippy::expect-used -A clippy::unwrap-used -A clippy::print-stdout -A clippy::uninlined-format-args -A clippy::useless-vec -A clippy::bool-assert-comparison -A clippy::needless_borrow -A clippy::redundant_closure -A clippy::result_large_err -A clippy::useless_conversion -A clippy::clone_on_copy
	cargo clippy --all-targets --features vsock --no-default-features -- -D warnings -A clippy::expect-used -A clippy::unwrap-used -A clippy::print-stdout -A clippy::uninlined-format-args -A clippy::useless-vec -A clippy::bool-assert-comparison -A clippy::needless_borrow -A clippy::redundant_closure -A clippy::result_large_err -A clippy::useless_conversion -A clippy::clone_on_copy
	@echo "✅ Linting complete"

# Development workflow helpers
dev: format lint check test
	@echo "✅ Development workflow checks complete"

# Production readiness check
production-ready: security test lint
	@echo "🚀 Production readiness check complete"