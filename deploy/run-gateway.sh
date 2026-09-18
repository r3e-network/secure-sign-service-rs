#!/usr/bin/env bash
set -euo pipefail

: "${SIGNER_PUBLIC_KEY:?SIGNER_PUBLIC_KEY is required}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/workload-identities.sh
. "$ROOT_DIR/lib/workload-identities.sh"

require_gateway_identities

GATEWAY_BIN="${GATEWAY_BIN:-/opt/neo-signer/bin/secure-sign-gateway}"

# Identities come from env, a 0600 file, or a credential fd — never argv.
exec "$GATEWAY_BIN" \
  --listen "${SIGNER_LISTEN:-10.78.0.1:9991}" \
  --enclave-cid "${SIGNER_CID:-2345}" \
  --enclave-port "${SIGNER_SERVICE_PORT:-9991}" \
  --network "${SIGNER_NETWORK:-860833102}" \
  --public-key "$SIGNER_PUBLIC_KEY" \
  --journal-db "${SIGNER_JOURNAL_DB:-/var/lib/neo-signer/anti-equivocation.redb}" \
  --legacy-journal "${SIGNER_LEGACY_JOURNAL:-${SIGNER_JOURNAL:-/var/lib/neo-signer/anti-equivocation.log}}" \
  --timeout-ms "${SIGNER_TIMEOUT_MS:-900}" \
  --economic-timeout-ms "${SIGNER_ECONOMIC_TIMEOUT_MS:-900}"
