#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <agg_ip>" >&2
  exit 1
fi

AGG_IP="$1"

CONFIGS=(
  ../configs/full-1.json
  ../configs/full-32.json
  ../configs/full-128.json
)

export RUST_LOG=info
export RUSTFLAGS="-C target-cpu=native"

# Update the configs file
for f in "${CONFIGS[@]}"; do
  tmp="$(mktemp "${f}.tmp.XXXXXX")"

  jq --indent 4 --arg agg "$AGG_IP" '
    def port(x): (x | split(":") | .[1]);

    .aggregator_addr = ($agg + ":" + port(.aggregator_addr))
  ' "$f" >"$tmp"

  mv "$tmp" "$f"
done

# Run decryptor
cargo run --release --bin exp_decryptor -- "${CONFIGS[0]}" --clear-db
