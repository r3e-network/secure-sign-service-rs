#!/usr/bin/env bash
set -euo pipefail

BASE="/home/ec2-user/neo/secure-sign-service-rs"
TOOL="$BASE/target/secure-sign-tools"

CID="${SIGNER_CID:-2345}"
SERVICE_PORT="${SIGNER_SERVICE_PORT:-9991}"
STARTUP_PORT="${SIGNER_STARTUP_PORT:-9992}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
KMS_CIPHERTEXT_BLOB_PATH="${KMS_CIPHERTEXT_BLOB_PATH:-/home/ec2-user/neo/secure/wallet-passphrase.kms.bin}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-3s}"
STATUS_CHECK_RETRIES="${STATUS_CHECK_RETRIES:-3}"
STARTUP_WAIT_RETRIES="${STARTUP_WAIT_RETRIES:-60}"
SIGNER_READY_RETRIES="${SIGNER_READY_RETRIES:-30}"
AWS_CLI_TIMEOUT_SECONDS="${AWS_CLI_TIMEOUT_SECONDS:-20}"

if [[ ! -x "$TOOL" ]]; then
  echo "missing tool binary: $TOOL" >&2
  exit 1
fi

if [[ ! -r "$KMS_CIPHERTEXT_BLOB_PATH" ]]; then
  echo "missing KMS ciphertext blob: $KMS_CIPHERTEXT_BLOB_PATH" >&2
  exit 1
fi

if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "AWS credentials/instance role not available for KMS decrypt" >&2
  exit 1
fi

PUBKEY="${SIGNER_PUBLIC_KEY:-}"
if [[ -z "$PUBKEY" ]]; then
  PUBKEY=$(python3 - <<'PY'
import base64, json
s=json.load(open('/home/ec2-user/neo/secure/council-wallet.json'))['accounts'][0]['contract']['script']
b=base64.b64decode(s)
print(b[2:35].hex())
PY
)
fi

for _ in $(seq 1 "$STATUS_CHECK_RETRIES"); do
  out="$(timeout "$TOOL_TIMEOUT" "$TOOL" status --cid "$CID" --port "$SERVICE_PORT" --public-key "$PUBKEY" 2>&1 || true)"
  if echo "$out" | grep -q 'status: Single'; then
    echo "Signer already unlocked."
    exit 0
  fi

  if ! echo "$out" | grep -Eiq 'Connection reset|Connection refused|timed out|transport::Error'; then
    break
  fi
  sleep 1
done

ATT_DOC=$(mktemp /tmp/nitro-attestation.XXXXXX.bin)
trap 'rm -f "$ATT_DOC"' EXIT

for _ in $(seq 1 "$STARTUP_WAIT_RETRIES"); do
  if timeout "$TOOL_TIMEOUT" "$TOOL" recipient-attestation --cid "$CID" --port "$STARTUP_PORT" --output "$ATT_DOC" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ ! -s "$ATT_DOC" ]]; then
  echo "failed to fetch recipient attestation document" >&2
  exit 1
fi

ATT_DOC_B64=$(base64 -w0 "$ATT_DOC")
recipient_arg="KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256,AttestationDocument=$ATT_DOC_B64"

aws_args=(
  kms decrypt
  --region "$AWS_REGION"
  --cli-connect-timeout "$AWS_CLI_TIMEOUT_SECONDS"
  --cli-read-timeout "$AWS_CLI_TIMEOUT_SECONDS"
  --ciphertext-blob "fileb://$KMS_CIPHERTEXT_BLOB_PATH"
  --recipient "$recipient_arg"
  --query "CiphertextForRecipient"
  --output text
)
if [[ -n "$KMS_KEY_ID" ]]; then
  aws_args+=(--key-id "$KMS_KEY_ID")
fi

CIPHERTEXT_FOR_RECIPIENT=$(aws "${aws_args[@]}")
if [[ -z "$CIPHERTEXT_FOR_RECIPIENT" || "$CIPHERTEXT_FOR_RECIPIENT" == "None" ]]; then
  echo "KMS decrypt did not return CiphertextForRecipient" >&2
  exit 1
fi

"$TOOL" start-recipient \
  --cid "$CID" \
  --port "$STARTUP_PORT" \
  --ciphertext-base64 "$CIPHERTEXT_FOR_RECIPIENT"

for _ in $(seq 1 "$SIGNER_READY_RETRIES"); do
  out="$(timeout "$TOOL_TIMEOUT" "$TOOL" status --cid "$CID" --port "$SERVICE_PORT" --public-key "$PUBKEY" 2>&1 || true)"
  if echo "$out" | grep -q 'status: Single'; then
    echo "Signer unlocked via KMS recipient attestation."
    exit 0
  fi
  sleep 1
done

echo "Signer failed to reach unlocked state after recipient startup." >&2
echo "$out" >&2
exit 1
