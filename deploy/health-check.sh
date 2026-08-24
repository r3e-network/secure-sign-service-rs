#!/usr/bin/env bash
set -euo pipefail

: "${SIGNER_PUBLIC_KEY:?SIGNER_PUBLIC_KEY is required}"

FAILURE_FILE=/run/neo-nitro-health.failures
FAILURE_THRESHOLD="${SIGNER_HEALTH_FAILURE_THRESHOLD:-3}"
TOOL=/opt/neo-signer/bin/secure-sign-tools
CID="${SIGNER_CID:-2345}"
PORT="${SIGNER_SERVICE_PORT:-9991}"

healthy=true
if ! nitro-cli describe-enclaves | jq -e --argjson cid "$CID" \
  '.[] | select(.EnclaveCID == $cid and .State == "RUNNING")' >/dev/null; then
  healthy=false
fi
if ! timeout 5s "$TOOL" status --cid "$CID" --port "$PORT" \
  --public-key "$SIGNER_PUBLIC_KEY" 2>&1 | grep -q 'status: Single'; then
  healthy=false
fi
if ! systemctl is-active --quiet neo-nitro-gateway.service; then
  healthy=false
fi

if $healthy; then
  printf '0\n' >"$FAILURE_FILE"
  exit 0
fi

failures=0
if [[ -r "$FAILURE_FILE" ]]; then
  read -r failures <"$FAILURE_FILE" || failures=0
fi
[[ "$failures" =~ ^[0-9]+$ ]] || failures=0
failures=$((failures + 1))
printf '%s\n' "$failures" >"$FAILURE_FILE"
logger -p auth.warning -t neo-nitro-health \
  "signer health check failed (${failures}/${FAILURE_THRESHOLD})"

if (( failures < FAILURE_THRESHOLD )); then
  exit 0
fi

printf '0\n' >"$FAILURE_FILE"
logger -p auth.alert -t neo-nitro-health \
  'restarting signer after consecutive health-check failures'
systemctl restart neo-nitro-signer.target
