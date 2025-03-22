#!/usr/bin/env bash

set -e -x

# parse arguments: `--bin signer-service-binary-path --wallet nep6-wallet-path.json --image docker-image-name`
BIN=""
WALLET=""
IMAGE=""

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
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--bin signer-service-binary-path] [--wallet nep6-wallet-path.json] [--image docker-image-name]"
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
docker build . -t $IMAGE --build-arg BIN=$BIN_NAME --build-arg WALLET=$WALLET_NAME

nitro-cli build-enclave --docker-uri $IMAGE:latest --output-file $IMAGE.eif

docker rmi $IMAGE
