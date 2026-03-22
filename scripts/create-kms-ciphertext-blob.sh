#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-ap-southeast-1}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
OUT_PATH="${KMS_CIPHERTEXT_BLOB_PATH:-/home/ec2-user/neo/secure/wallet-passphrase.kms.bin}"

if [[ -z "$KMS_KEY_ID" ]]; then
  echo "KMS_KEY_ID is required" >&2
  exit 1
fi

if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "AWS credentials/instance role not available" >&2
  exit 1
fi

TMP_PLAINTEXT=$(mktemp /tmp/wallet-passphrase.XXXXXX)
trap 'shred -u "$TMP_PLAINTEXT" 2>/dev/null || rm -f "$TMP_PLAINTEXT"' EXIT

read -rsp "Enter wallet passphrase (input hidden): " WALLET_PASSPHRASE
echo
if [[ -z "$WALLET_PASSPHRASE" ]]; then
  echo "passphrase cannot be empty" >&2
  exit 1
fi
printf "%s" "$WALLET_PASSPHRASE" > "$TMP_PLAINTEXT"
unset WALLET_PASSPHRASE

CIPHERTEXT_B64=$(aws kms encrypt \
  --region "$AWS_REGION" \
  --key-id "$KMS_KEY_ID" \
  --plaintext "fileb://$TMP_PLAINTEXT" \
  --query CiphertextBlob \
  --output text)

mkdir -p "$(dirname "$OUT_PATH")"
python3 - "$CIPHERTEXT_B64" "$OUT_PATH" <<'PY'
import base64, sys
blob_b64, out_path = sys.argv[1], sys.argv[2]
with open(out_path, "wb") as f:
    f.write(base64.b64decode(blob_b64))
PY

chmod 600 "$OUT_PATH"
echo "Wrote KMS ciphertext blob to: $OUT_PATH"
