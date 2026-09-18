#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../deploy/lib/workload-identities.sh
. "$ROOT_DIR/deploy/lib/workload-identities.sh"

fail() {
    echo "check-gateway-identities: $*" >&2
    exit 1
}

# Static proof that the systemd actual entry cannot put tokens on argv.
unit="$ROOT_DIR/deploy/systemd/neo-nitro-gateway.service"
grep -q 'ExecStart=/opt/neo-signer/bin/run-gateway.sh' "$unit" || fail "systemd unit ExecStart is not run-gateway.sh"
grep -q 'EnvironmentFile=/etc/neo-signer/signer.env' "$unit" || fail "systemd unit missing EnvironmentFile"
grep -q 'LoadCredential=workload-identities:' "$unit" || fail "systemd unit missing LoadCredential"
if grep -E 'ExecStart=.*(--workload-identities[= ]|GATEWAY_WORKLOAD_IDENTITIES=)' "$unit"; then
    fail "systemd ExecStart must not carry identity table or token"
fi
if grep -E -- '--workload-identities([= ]|$)' "$ROOT_DIR/deploy/run-gateway.sh"; then
    fail "run-gateway.sh must not pass identities on argv"
fi
grep -q 'require_gateway_identities' "$ROOT_DIR/deploy/run-gateway.sh" || fail "run-gateway.sh must call require_gateway_identities"
grep -q 'GATEWAY_WORKLOAD_IDENTITIES_FILE' "$ROOT_DIR/deploy/signer.env.example" || fail "env template missing FILE source"

unset GATEWAY_WORKLOAD_IDENTITIES GATEWAY_WORKLOAD_IDENTITIES_FILE GATEWAY_WORKLOAD_IDENTITIES_FD CREDENTIALS_DIRECTORY
if require_gateway_identities 2>/tmp/identities-missing.err; then
    fail "missing identities must fail"
fi
grep -q 'is required' /tmp/identities-missing.err || fail "missing identities must print a clear error"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
token='dBFT-node:consensus:'"$(printf 'aa%.0s' {1..32})"

GATEWAY_WORKLOAD_IDENTITIES="$token"
require_gateway_identities || fail "env identities should be accepted"
unset GATEWAY_WORKLOAD_IDENTITIES

file="$tmp/identities"
printf '%s\n' "$token" >"$file"
chmod 0600 "$file"
GATEWAY_WORKLOAD_IDENTITIES_FILE="$file"
require_gateway_identities || fail "0600 identities file should be accepted"

chmod 0644 "$file"
if require_gateway_identities 2>/tmp/identities-mode.err; then
    fail "0644 identities file must be rejected"
fi
grep -q '0600' /tmp/identities-mode.err || fail "mode failure must mention 0600"
chmod 0600 "$file"

GATEWAY_WORKLOAD_IDENTITIES="$token"
if require_gateway_identities 2>/tmp/identities-both.err; then
    fail "env+file together must be rejected"
fi
grep -q 'exactly one' /tmp/identities-both.err || fail "dual source error must be explicit"
unset GATEWAY_WORKLOAD_IDENTITIES GATEWAY_WORKLOAD_IDENTITIES_FILE

# Prove the systemd wrapper can exec without putting the token on argv.
stub="$tmp/secure-sign-gateway"
argv_log="$tmp/argv"
cat >"$stub" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"${ARGV_LOG:?}"
EOF
chmod 0755 "$stub"

export GATEWAY_BIN="$stub"
export ARGV_LOG="$argv_log"
export SIGNER_PUBLIC_KEY='02'"$(printf 'ab%.0s' {1..32})"
export GATEWAY_WORKLOAD_IDENTITIES="$token"
"$ROOT_DIR/deploy/run-gateway.sh"
if grep -F -- "$token" "$argv_log"; then
    fail "run-gateway.sh leaked the identity table onto argv"
fi
if grep -E -- '--workload-identities' "$argv_log"; then
    fail "run-gateway.sh passed --workload-identities"
fi
grep -q -- '--listen' "$argv_log" || fail "stub gateway was not executed"
if grep -F -- "$token" "$argv_log" /tmp/identities-missing.err /tmp/identities-mode.err /tmp/identities-both.err; then
    fail "identity token appeared in check logs"
fi

echo "gateway identity production entry: ok"
