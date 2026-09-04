#!/usr/bin/env bash

set -euo pipefail

# parse arguments:
# --wallet nep6-wallet-path.json [--bin signer-service-binary-path] [--image docker-image-name]
# [--private-key private-key, or --key] [--signing-certificate signing-certificate, or --cert]
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BIN="${SCRIPT_DIR}/../../target/secure-sign-vsock"
IMAGE="secure-sign-nitro"
WALLET=""
KEY=""
CERT=""

# SSM Run Command does not guarantee HOME. Nitro CLI needs explicit writable
# artifacts storage and the package-provided kernel/init blobs to build an EIF.
export NITRO_CLI_ARTIFACTS="${NITRO_CLI_ARTIFACTS:-${TMPDIR:-/tmp}/nitro-cli-artifacts}"
export NITRO_CLI_BLOBS="${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs}"
install -d -m 0700 "$NITRO_CLI_ARTIFACTS"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin)
            [[ $# -ge 2 ]] || { echo "Missing value for --bin" >&2; exit 2; }
            BIN=$2
            shift 2
            ;;
        --wallet)
            [[ $# -ge 2 ]] || { echo "Missing value for --wallet" >&2; exit 2; }
            WALLET=$2
            shift 2
            ;;
        --image)
            [[ $# -ge 2 ]] || { echo "Missing value for --image" >&2; exit 2; }
            IMAGE=$2
            shift 2
            ;;
        --key|--private-key)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            KEY=$2
            shift 2
            ;;
        --cert|--signing-certificate)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
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

if [[ -z "$WALLET" || ! -f "$WALLET" ]]; then
    echo "Error: --wallet must reference an existing NEP-6 wallet" >&2
    exit 2
fi
if [[ ! -f "$BIN" ]]; then
    echo "Error: signer binary not found: $BIN" >&2
    exit 2
fi
if [[ -n "$KEY" && ! -f "$KEY" ]]; then
    echo "Error: signing private key not found: $KEY" >&2
    exit 2
fi
if [[ -n "$CERT" && ! -f "$CERT" ]]; then
    echo "Error: signing certificate not found: $CERT" >&2
    exit 2
fi
if [[ -n "$CERT" && -z "$KEY" ]]; then
    echo "Error: --cert requires --key" >&2
    exit 2
fi

BUILD_CONTEXT=$(mktemp -d "${TMPDIR:-/tmp}/secure-sign-nitro.XXXXXX")
cleanup() {
    rm -rf -- "$BUILD_CONTEXT"
}
trap cleanup EXIT INT TERM

install -m 0755 "$BIN" "$BUILD_CONTEXT/secure-sign-vsock"
install -m 0600 "$WALLET" "$BUILD_CONTEXT/nep6-wallet.json"
install -m 0644 "$SCRIPT_DIR/Dockerfile" "$BUILD_CONTEXT/Dockerfile"

echo "Building Docker image $IMAGE from an ephemeral context"
BUILD_ARGS=(
    --build-arg BIN=secure-sign-vsock
    --build-arg WALLET=nep6-wallet.json
    --build-arg "ENABLE_SIGN_TRANSACTION=${ENABLE_SIGN_TRANSACTION:-false}"
    --build-arg "GAS_SWEEP_DESTINATION_ADDRESS=${GAS_SWEEP_DESTINATION_ADDRESS:-}"
    --build-arg "GAS_SWEEP_DESTINATION_SCRIPT_HASH=${GAS_SWEEP_DESTINATION_SCRIPT_HASH:-}"
)
docker build \
    "${BUILD_ARGS[@]}" \
    --tag "$IMAGE" \
    "$BUILD_CONTEXT"

OUTPUT_EIF="${PWD}/${IMAGE}.eif"
rm -f -- "$OUTPUT_EIF"

if [[ -n "$KEY" ]]; then
    if [[ -n "$CERT" ]]; then
        nitro-cli build-enclave --docker-uri "$IMAGE:latest" --output-file "$OUTPUT_EIF" --private-key "$KEY" --signing-certificate "$CERT"
    else
        nitro-cli build-enclave --docker-uri "$IMAGE:latest" --output-file "$OUTPUT_EIF" --private-key "$KEY"
    fi
else
    nitro-cli build-enclave --docker-uri "$IMAGE:latest" --output-file "$OUTPUT_EIF"
fi

docker image rm "$IMAGE" >/dev/null
echo "Built $OUTPUT_EIF"
