#!/usr/bin/env bash
set -euo pipefail

BASE="/home/ec2-user/neo/secure-sign-service-rs"
PASS_FILE="/home/ec2-user/neo/secure/.wallet-pass"
CID=2345
PORT=9991
DECRYPT_PORT=9992

if [[ ! -s "$PASS_FILE" ]]; then
  echo "missing passphrase file: $PASS_FILE" >&2
  exit 1
fi

PUBKEY=$(python3 - <<'PY'
import base64, json
s=json.load(open('/home/ec2-user/neo/secure/council-wallet.json'))['accounts'][0]['contract']['script']
b=base64.b64decode(s)
print(b[2:35].hex())
PY
)

# wait briefly for signer service endpoint to come up
for _ in {1..20}; do
  STATUS_OUT=$($BASE/target/secure-sign-tools status --cid "$CID" --port "$PORT" --public-key "$PUBKEY" 2>&1 || true)
  if echo "$STATUS_OUT" | grep -q 'status: Single'; then
    exit 0
  fi
  if ! echo "$STATUS_OUT" | grep -q 'Connection reset\|timed out\|transport::Error\|Connection refused'; then
    break
  fi
  sleep 1
done

/usr/bin/expect <<'EXP'
set timeout 30
set pass [string trim [exec cat /home/ec2-user/neo/secure/.wallet-pass]]
spawn /home/ec2-user/neo/secure-sign-service-rs/target/secure-sign-tools decrypt --cid 2345 --port 9992
expect {
  -re {[Pp]assword of the wallet:} { send -- "$pass\r" }
  timeout { exit 1 }
}
expect eof
catch wait result
set exit_status [lindex $result 3]
exit $exit_status
EXP

$BASE/target/secure-sign-tools status --cid "$CID" --port "$PORT" --public-key "$PUBKEY" | grep -q 'status: Single'
