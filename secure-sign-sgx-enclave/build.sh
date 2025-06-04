#!/bin/bash

# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

set -e

ALIYUN=false
SIGN_KEY="sgx_sign_private_key.pem"
SGX_DEBUG=false
SGX_MODE="HW"
SGX_CONFIG="Enclave.config.xml"
SHOW_HELP=false

# Parse arguments: --sign-key <path> [--aliyun] [--sgx-config <path>] [--sgx-debug] [--sgx-mode <mode>]
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build script for SGX enclave"
    echo ""
    echo "Options:"
    echo "  --sign-key <path>     Path to the SGX signing key file (default: sgx_sign_private_key.pem)"
    echo "  --aliyun              Build on Alibaba Cloud with Alibaba TEE SDK (default: false)"
    echo "  --sgx-config <path>   Path to the SGX config file (default: Enclave.config.xml)"
    echo "  --sgx-debug           Enable SGX debug mode (default: false)"
    echo "  --sgx-mode <mode>     SGX mode: HW or SW (default: HW)"
    echo "  --help                Show this help message"
    echo ""
    echo "Note: Wallet files are now loaded at runtime, not embedded at compile time."
    echo "To generate a signing key: openssl genrsa -out sgx_sign_private_key.pem -3 3072"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign-key)
            SIGN_KEY=$2
            shift 2
            ;;
        --aliyun)
            ALIYUN=true
            shift 1
            ;;
        --sgx-config)
            SGX_CONFIG=$2
            shift 2
            ;;
        --sgx-debug)
            SGX_DEBUG=true
            shift 1
            ;;
        --sgx-mode)
            SGX_MODE=$2
            shift 2
            ;;
        --help)
            SHOW_HELP=true
            shift 1
            ;;
        *)
            echo "Error: Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    show_help
    exit 0
fi

# Validate SGX mode
if [ "$SGX_MODE" != "HW" ] && [ "$SGX_MODE" != "SW" ]; then
    echo "Error: SGX_MODE must be either 'HW' or 'SW'"
    exit 1
fi

# Check if signing key exists
if [ ! -f "$SIGN_KEY" ]; then
    echo "Error: Signing key '$SIGN_KEY' not found"
    echo "Generate one with: openssl genrsa -out $SIGN_KEY -3 3072"
    exit 1
fi

# Check if config file exists
if [ ! -f "$SGX_CONFIG" ]; then
    echo "Error: SGX config file '$SGX_CONFIG' not found"
    exit 1
fi

# Source SGX SDK environment
if [ "$ALIYUN" = true ]; then
    echo "Using Alibaba Cloud TEE SDK..."
    source /opt/alibaba/teesdk/intel/sgxsdk/environment
else
    echo "Using Intel SGX SDK..."
    if [ -f "/opt/intel/sgxsdk/environment" ]; then
        source /opt/intel/sgxsdk/environment
    else
        echo "Error: Intel SGX SDK not found at /opt/intel/sgxsdk"
        echo "Please install Intel SGX SDK or use --aliyun for Alibaba Cloud"
        exit 1
    fi
fi

# Export build variables
export SIGN_KEY=$SIGN_KEY
export SGX_CONFIG=$SGX_CONFIG
export SGX_DEBUG=$SGX_DEBUG
export SGX_MODE=$SGX_MODE

echo "Building SGX enclave with:"
echo "  SGX Mode: $SGX_MODE"
echo "  Debug: $SGX_DEBUG"
echo "  Config: $SGX_CONFIG"
echo "  Signing Key: $SIGN_KEY"

# Build the enclave
make clean
make sgx

echo "SGX enclave build completed successfully!"
echo "Generated files:"
ls -la *.so *.signed.so 2>/dev/null || echo "  (No .so files found - check build output)"
