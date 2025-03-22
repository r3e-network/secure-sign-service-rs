#!/bin/bash

set -e

# parse arguments: `--debug --cpu-count N --memory xx --cid CID --path PATH`
CPU_COUNT=2
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
            CPU_COUNT=$2
            shift 2
            ;;
        --memory)
            MEMORY=$2
            shift 2
            ;;
        --cid)
            CID=$2
            shift 2
            ;;
        --eif-path)
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

# if debug mode is true, then run in debug mode
if [ "$DEBUG" == "true" ]; then
    nitro-cli run-enclave --cpu-count $CPU_COUNT --memory $MEMORY --enclave-cid $CID --eif-path $EIF_PATH --debug-mode
else
    nitro-cli run-enclave --cpu-count $CPU_COUNT --memory $MEMORY --enclave-cid $CID --eif-path $EIF_PATH
fi

sleep 2
nitro-cli describe-enclaves

# to stop the enclave, run:
# nitro-cli terminate-enclave --enclave-id <enclave-id>

# console in debug-mode:
# nitro-cli console --enclave-id <enclave-id>
