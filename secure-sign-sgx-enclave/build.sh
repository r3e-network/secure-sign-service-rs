#!/bin/bash

# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

set -e

WALLET=""
ALIYUN=false
SIGN_KEY="sgx_sign_private_key.pem"
SGX_DEBUG=false
SGX_MODE=HW
SGX_CONFIG="Enclave.config.production.xml"
SHOW_HELP=false

# parse arguments: --wallet-path <path> --sign-key <path> [--aliyun] [--sgx-config <path>] [--sgx-debug]
show_help() {
    echo "Usage: $0 --wallet-path <path> --sign-key <path> [--aliyun] [--sgx-config <path>] [--sgx-debug] [--sgx-mode]"
    echo ""
    echo "  --wallet-path <path>  Path to the wallet file"
    echo "  --sign-key <path>     Path to the sign key file (default: sgx_sign_private_key.pem)"
    echo "  --aliyun              If build on aliyun (default: false)"
    echo "  --sgx-config <path>   Path to the SGX config file (default: Enclave.config.production.xml)"
    echo "  --sgx-debug           Enable SGX debug mode (default: false)"
    echo "  --sgx-mode            SGX mode (HW or SW, default: HW)"
    echo "  --help                Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wallet-path)
            WALLET=$2
            shift 2
            ;;
        --sign-key) # To generate sign key, run `openssl genrsa -out sign-key-path -3 3072`
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
            SGX_DEBUG=$2
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
            echo "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    show_help
    exit 0
fi

# check $WALLET is a file or not
if [ ! -f "$WALLET" ]; then
    echo "Error: $WALLET is not set or not a file"
    show_help
    exit 1
fi

# check $SIGN_KEY is a file or not
if [ ! -f "$SIGN_KEY" ]; then
    echo "Error: $SIGN_KEY is not set or not a file"
    show_help
    exit 1
fi

# source /opt/alibaba/teesdk/intel/sgxsdk/environment # if Aliyun
# See https://help.aliyun.com/zh/ecs/user-guide/build-an-sgx-encrypted-computing-environment
if [ "$ALIYUN" = true ]; then
    source /opt/alibaba/teesdk/intel/sgxsdk/environment
fi

export WALLET_PATH=$WALLET
export SIGN_KEY=$SIGN_KEY
export SGX_CONFIG=$SGX_CONFIG
export SGX_DEBUG=$SGX_DEBUG
export SGX_MODE=$SGX_MODE

make sgx
