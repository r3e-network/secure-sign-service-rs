#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EIF_PATH="${EIF_PATH:-$ROOT_DIR/scripts/nitro/secure-sign-nitro-council-arm64.eif}"
CIPHERTEXT_PATH="${KMS_CIPHERTEXT_BLOB_PATH:-/home/ec2-user/neo/secure/wallet-passphrase.kms.bin}"
SIGNER_ENV_PATH="${SIGNER_ENV_PATH:-/home/ec2-user/neo/secure/kms-auto-unlock.env}"

for file in \
  "$ROOT_DIR/target/secure-sign-tools" \
  "$ROOT_DIR/target/secure-sign-gateway" \
  "$ROOT_DIR/scripts/auto-unlock-kms-recipient.sh" \
  "$EIF_PATH" \
  "$CIPHERTEXT_PATH" \
  "$SIGNER_ENV_PATH"; do
  [[ -s "$file" ]] || { echo "missing deployment artifact: $file" >&2; exit 1; }
done

if ! id neo-signer >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/neo-signer --shell /sbin/nologin neo-signer
fi

install -d -m 0755 /opt/neo-signer/bin /opt/neo-signer/enclave
install -d -o neo-signer -g neo-signer -m 0700 /var/lib/neo-signer
install -d -m 0750 /etc/neo-signer
install -m 0755 "$ROOT_DIR/target/secure-sign-tools" /opt/neo-signer/bin/
install -m 0755 "$ROOT_DIR/target/secure-sign-gateway" /opt/neo-signer/bin/
install -m 0755 "$ROOT_DIR/scripts/auto-unlock-kms-recipient.sh" /opt/neo-signer/bin/
install -m 0755 "$ROOT_DIR/deploy/run-gateway.sh" /opt/neo-signer/bin/
install -m 0755 "$ROOT_DIR/deploy/health-check.sh" /opt/neo-signer/bin/
install -m 0600 "$EIF_PATH" /opt/neo-signer/enclave/council-signer.eif
install -o neo-signer -g neo-signer -m 0600 "$CIPHERTEXT_PATH" \
  /var/lib/neo-signer/wallet-passphrase.kms.bin
install -m 0640 "$SIGNER_ENV_PATH" /etc/neo-signer/signer.env
chown root:neo-signer /etc/neo-signer/signer.env
install -m 0644 "$ROOT_DIR"/deploy/systemd/* /etc/systemd/system/

systemctl daemon-reload
systemctl enable neo-nitro-signer.target neo-nitro-health.timer
