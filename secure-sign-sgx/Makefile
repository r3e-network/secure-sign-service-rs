# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

release:
	cargo +nightly build --release
	cp target/release/secure-sign-sgx target/secure-sign-sgx

debug:
	cargo +nightly build
	cp target/debug/secure-sign-sgx target/secure-sign-sgx

clean:
	cargo clean
	rm -f ../target/secure-sign-sgx
