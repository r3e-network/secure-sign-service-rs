#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

generated=(
  secure-sign-rpc/src/servicepb.rs
  secure-sign-rpc/src/startpb.rs
  secure-sign-core/src/neo/signpb.rs
)

tmpdir="$(mktemp -d)"
restore_and_cleanup() {
  local f base
  for f in "${generated[@]}"; do
    base="$(basename "$f")"
    if [[ -f "$tmpdir/$base" ]]; then
      cp "$tmpdir/$base" "$f"
    fi
  done
  rm -rf "$tmpdir"
}
trap restore_and_cleanup EXIT

for f in "${generated[@]}"; do
  cp "$f" "$tmpdir/$(basename "$f")"
done

touch \
  secure-sign-rpc/build.rs \
  secure-sign-rpc/proto/servicepb.proto \
  secure-sign-rpc/proto/startpb.proto \
  secure-sign-core/build.rs \
  secure-sign-core/proto/signpb.proto

cargo build -p secure-sign-core -p secure-sign-rpc --locked

status=0
for f in "${generated[@]}"; do
  if ! cmp -s "$f" "$tmpdir/$(basename "$f")"; then
    echo "Generated $f drifted from locked tonic-build/prost-build output." >&2
    diff -u "$tmpdir/$(basename "$f")" "$f" >&2 || true
    status=1
  fi
done

exit "$status"
