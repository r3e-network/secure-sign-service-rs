#!/bin/bash

set -e

SGX_BIN=./secure-sign-sgx/target/secure-sign-sgx
ENCLAVE_BIN=./secure-sign-sgx-enclave/secure_sign_sgx_enclave.signed.so
IS_DAEMON=false

# parse the arguments "--sgx-bin <path> --enclave-bin <path> --daemon"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sgx-bin)
            SGX_BIN=$2
            shift 2
            ;;
        --enclave-bin)
            ENCLAVE_BIN=$2
            shift 2
            ;;
        --daemon)
            IS_DAEMON=true
            shift 1
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--sgx-bin <path>] [--enclave-bin <path>] [--daemon]"
            exit 1
            ;;
    esac
done

if [ ! -f "$SGX_BIN" ]; then
    echo "SGX binary not found at $SGX_BIN"
    exit 1
fi

# The signer must be told which Neo network it signs for; there is no default.
# Mainnet magic is 860833102.
if [ -z "${SIGNER_NETWORK:-}" ]; then
    echo "SIGNER_NETWORK is not set: export the Neo network magic this signer may sign (mainnet: 860833102)"
    exit 1
fi

if [ ! -f "$ENCLAVE_BIN" ]; then
    echo "Enclave binary not found at $ENCLAVE_BIN"
    exit 1
fi

if [ "$IS_DAEMON" = true ]; then
    nohup $SGX_BIN run --enclave $ENCLAVE_BIN --network "$SIGNER_NETWORK" > sgx.log 2>&1 &
else
    $SGX_BIN run --enclave $ENCLAVE_BIN --network "$SIGNER_NETWORK"
fi
