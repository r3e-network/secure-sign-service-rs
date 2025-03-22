# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

# prerequisites:
# for vsock(aws nitro uses it): rustup target add x86_64-unknown-linux-musl
# for sgx: rustup target add x86_64-fortanix-unknown-sgx
ARCH=$(shell uname -m)
ifeq ($(ARCH), x86_64)
	VSOCK_TARGET=x86_64-unknown-linux-musl
else ifeq ($(ARCH), arm64)
	VSOCK_TARGET=aarch64-unknown-linux-musl
else
	$(error Unsupported architecture: $(ARCH))
endif

SGX_TARGET=x86_64-fortanix-unknown-sgx

# build tcp server, output name is secure-sign-tcp
tcp:
	cargo build --release --features tcp --no-default-features
	mv target/release/secure-sign target/secure-sign-tcp

# build vsock server, output name is secure-sign-vsock
vsock:
	cargo build --release --target=${VSOCK_TARGET} --features vsock --no-default-features
	mv target/release/secure-sign target/secure-sign-vsock

clean:
	cargo clean
	rm -f target/secure-sign-tcp target/secure-sign-vsock target/secure-sign-sgx