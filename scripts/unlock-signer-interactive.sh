#!/usr/bin/env bash
set -euo pipefail

BASE="/home/ec2-user/neo/secure-sign-service-rs"
CID=2345
PORT=9991
DECRYPT_PORT=9992
PUBKEY=$(python3 - <<PY
import base64, json
s=json.load(open(/home/ec2-user/neo/secure/council-wallet.json))[accounts][0][contract][script]
b=base64.b64decode(s)
print(b[2:35].hex())
PY
)

status_out="$($BASE/target/secure-sign-tools status --cid "$CID" --port "$PORT" --public-key "$PUBKEY" 2>&1 || true)"
if echo "$status_out" | grep -q status: Single; then
  echo "Signer already unlocked (status: Single)."
  exit 0
fi

echo "Unlocking Nitro signer now (passphrase is read from TTY and never stored on host)..."
"$BASE/target/secure-sign-tools" decrypt --cid "$CID" --port "$DECRYPT_PORT"

"$BASE/target/secure-sign-tools" status --cid "$CID" --port "$PORT" --public-key "$PUBKEY"
echo "If this shows status: Single, neo-cli will auto-attempt SignClient consensus start."
