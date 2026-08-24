#!/usr/bin/env bash

set -euo pipefail

# parse arguments: `--debug --cpu-count N --memory xx --cid CID --path PATH`
CPU_COUNT=2
case "$(uname -m)" in
    aarch64|arm64) CPU_COUNT=1 ;;
esac
MEMORY=512
DEBUG=false
CID=2345
EIF_PATH=secure-sign-nitro.eif

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG=true
            shift
            ;;
        --cpu-count)
            [[ $# -ge 2 ]] || { echo "Missing value for --cpu-count" >&2; exit 2; }
            CPU_COUNT=$2
            shift 2
            ;;
        --memory)
            [[ $# -ge 2 ]] || { echo "Missing value for --memory" >&2; exit 2; }
            MEMORY=$2
            shift 2
            ;;
        --cid)
            [[ $# -ge 2 ]] || { echo "Missing value for --cid" >&2; exit 2; }
            CID=$2
            shift 2
            ;;
        --eif-path)
            [[ $# -ge 2 ]] || { echo "Missing value for --eif-path" >&2; exit 2; }
            EIF_PATH=$2
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--debug] [--cpu-count N(default: 2)] [--memory MB(default: 512(in MB))]" \
                " [--cid CID(default: 2345)] [--eif-path enclave-image-file(default: secure-sign-nitro.eif)]"
            exit 1
            ;;
    esac
done

[[ "$CPU_COUNT" =~ ^[1-9][0-9]*$ ]] || { echo "--cpu-count must be a positive integer" >&2; exit 2; }
[[ "$MEMORY" =~ ^[1-9][0-9]*$ ]] || { echo "--memory must be a positive integer" >&2; exit 2; }
[[ "$CID" =~ ^[1-9][0-9]*$ ]] || { echo "--cid must be a positive integer" >&2; exit 2; }
[[ -f "$EIF_PATH" ]] || { echo "Enclave image not found: $EIF_PATH" >&2; exit 2; }

# if debug mode is true, then run in debug mode
if [[ "$DEBUG" == "true" ]]; then
    nitro-cli run-enclave --cpu-count "$CPU_COUNT" --memory "$MEMORY" --enclave-cid "$CID" --eif-path "$EIF_PATH" --debug-mode
else
    nitro-cli run-enclave --cpu-count "$CPU_COUNT" --memory "$MEMORY" --enclave-cid "$CID" --eif-path "$EIF_PATH"
fi

sleep 2
nitro-cli describe-enclaves

# to stop the enclave, run:
# nitro-cli terminate-enclave --enclave-id <enclave-id>

# console in debug-mode:
# nitro-cli console --enclave-id <enclave-id>
