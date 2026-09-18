#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files=()

while IFS= read -r file; do
  case "$file" in
    secure-sign-rpc/src/servicepb.rs | secure-sign-rpc/src/startpb.rs)
      # build.rs regenerates these files through tonic-build / prettyplease.
      continue
      ;;
  esac
  files+=("$ROOT_DIR/$file")
done < <(git -C "$ROOT_DIR" ls-files '*.rs')

if ((${#files[@]} == 0)); then
  echo "No tracked Rust files found." >&2
  exit 1
fi

rustfmt --edition 2021 --check --config skip_children=true "${files[@]}"
"$ROOT_DIR/scripts/check-generated.sh"
