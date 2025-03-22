# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

ARCH=$(shell uname -m)

# rustup target add x86_64-unknown-linux-musl or rustup target add aarch64-unknown-linux-musl
ifeq ($(ARCH), x86_64)
	VSOCK_TARGET=x86_64-unknown-linux-musl
else ifeq ($(ARCH), arm64)
	VSOCK_TARGET=aarch64-unknown-linux-musl
else
	$(error Unsupported architecture: $(ARCH))
endif

.DEFAULT_GOAL := help

tcp:
	cargo build --release --features tcp --no-default-features
	mv target/release/secure-sign target/secure-sign-tcp

vsock:
	cargo build --release --target=${VSOCK_TARGET} --features vsock --no-default-features
	mv target/${VSOCK_TARGET}/release/secure-sign target/secure-sign-vsock

WALLET_PATH ?= nep6_wallet.json
SIGN_KEY ?= sgx_sign_private_key.pem

WALLET_PATH := $(shell realpath $(WALLET_PATH))
SIGN_KEY := $(shell realpath $(SIGN_KEY))
sgx:
	cd secure-sign-sgx-enclave && ./build.sh --wallet-path $(WALLET_PATH) --sign-key $(SIGN_KEY)
	cd secure-sign-sgx && ./build.sh --release

tools:
	cargo build --release --features tcp --no-default-features
	mv target/release/secure-sign target/secure-sign-tools

clean:
	cargo clean
	rm -f target/secure-sign-tcp target/secure-sign-vsock target/secure-sign-tools
	cd secure-sign-sgx-enclave && make clean
	cd secure-sign-sgx && make clean

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  tcp   -- build tcp server(for test/mock in most cases), output is target/secure-sign-tcp"
	@echo "  vsock -- build vsock server(for aws nitro), output is target/secure-sign-vsock"
	@echo "  sgx   -- build sgx server(for intel sgx enclave), output is secure-sign-sgx/target/secure-sign-sgx"
	@echo "  tools -- build tools(for mock, decrypt wallet and get account status), output is target/secure-sign-tools"
	@echo "  clean -- clean all build artifacts"
	@echo "  help  -- show this help message"
	@echo ""
	@echo "Prerequisites: "
	@echo "  - for vsock: rustup target add x86_64-unknown-linux-musl"
	@echo "  - for sgx: install intel sgx sdk"
