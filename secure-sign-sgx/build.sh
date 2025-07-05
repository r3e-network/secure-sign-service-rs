#!/bin/bash

# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

set -e

SGX_MODE="HW"
ALIYUN=false
RELEASE=false

show_help() {
    echo "Usage: $0 [--sgx-model <HW|SW>] [--aliyun]"
    echo ""
    echo "  --sgx-model <HW|SW>  SGX mode (HW or SW, default: HW)"
    echo "  --aliyun             If build on aliyun (default: false)"
    echo "  --help               Show this help message"
}

# parse arguments: --sgx-model [--aliyun] [--release] [--help]
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sgx-model)
            SGX_MODE=$2
            shift 2
            ;;
        --aliyun)
            ALIYUN=true
            shift 1
            ;;
        --release)
            RELEASE=true
            shift 1
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

# source /opt/alibaba/teesdk/intel/sgxsdk/environment # if Aliyun
# See https://help.aliyun.com/zh/ecs/user-guide/build-an-sgx-encrypted-computing-environment
if [ "$ALIYUN" = true ]; then
    source /opt/alibaba/teesdk/intel/sgxsdk/environment
fi

export SGX_MODE=$SGX_MODE

if [ "$RELEASE" = true ]; then
    make release
else
    make debug
fi
