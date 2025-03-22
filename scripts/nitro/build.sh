#!/bin/bash

set -e

# parse arguments:
# --wallet nep6-wallet-path.json [--bin signer-service-binary-path] [--image docker-image-name]
# [--private-key private-key, or --key] [--signing-certificate signing-certificate, or --cert]
BIN="../../target/secure-sign-vsock"
IMAGE="secure-sign-nitro"
WALLET=""
KEY=""
CERT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin)
            BIN=$2
            shift 2
            ;;
        --wallet)
            WALLET=$2
            shift 2
            ;;
        --image)
            IMAGE=$2
            shift 2
            ;;
        --key|--private-key)
            KEY=$2
            shift 2
            ;;
        --cert|--signing-certificate)
            CERT=$2
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 --wallet nep6-wallet-path.json [--bin signer-service-binary-path] [--image docker-image-name] " \
                "[--private-key private-key, or --key] [--signing-certificate signing-certificate, or --cert]"
            echo "About --private-key and --signing-certificate: https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-build-enclave.html"
            exit 1
            ;;
    esac
done

cp $BIN .
cp $WALLET .

# get file name from BIN and WALLET
BIN_NAME=$(basename $BIN)
WALLET_NAME=$(basename $WALLET)
if [ ! -f "$BIN_NAME" ] || [ ! -f "$WALLET_NAME" ]; then
    echo "Error: Required files(signer-service-binary file or nep6-wallet file) not found"
    exit 1
fi

# build with ARG BIN and WALLET
echo "Building docker image $IMAGE with binary $BIN_NAME and wallet $WALLET_NAME"
docker build --build-arg BIN=$BIN_NAME --build-arg WALLET=$WALLET_NAME -t $IMAGE .

# rm previous enclave image file if exists
if [ -f "$IMAGE.eif" ]; then
    rm $IMAGE.eif
fi

if [ ! -z "$KEY" ]; then
    if [ ! -z "$CERT" ]; then
        nitro-cli build-enclave --docker-uri $IMAGE:latest --output-file $IMAGE.eif --private-key $KEY --signing-certificate $CERT
    else
        nitro-cli build-enclave --docker-uri $IMAGE:latest --output-file $IMAGE.eif --private-key $KEY
    fi
else
    nitro-cli build-enclave --docker-uri $IMAGE:latest --output-file $IMAGE.eif
fi

docker rmi $IMAGE
