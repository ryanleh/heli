#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <agg_ip> <dec_ip>" >&2
  exit 1
fi

AGG_IP="$1"
DEC_IP="$2"
shift 2

CONFIGS=(
  configs/simplified-1.json
  configs/simplified-32.json
  configs/simplified-128.json
)

export RUST_LOG=info

# Update the configs file
for f in "${CONFIGS[@]}"; do
  tmp="$(mktemp "${f}.tmp.XXXXXX")"

  jq --indent 4 --arg agg "$AGG_IP" --arg dec "$DEC_IP" '
    def port(x): (x | split(":") | .[1]);

    .aggregator_addr = ($agg + ":" + port(.aggregator_addr)) |
    .decryptor_addr  = ($dec + ":" + port(.decryptor_addr))
  ' "$f" >"$tmp"

  mv "$tmp" "$f"
done

# Run setup once
echo "============================================================"
echo "Running setup"
echo "------------------------------------------------------------"

cargo run --release --bin exp_client -- "${CONFIGS[0]}" --mode sim-setup --clear-db
sleep 2

# Run the rest of the workflow for each config
for f in "${CONFIGS[@]}"; do
  echo -e "\n\n"
  echo "============================================================"
  echo "Running config: ${f}"
  echo "------------------------------------------------------------"
  echo "---------------------"
  echo "Generating queries:"
  echo -e "---------------------\n"
  cargo run --release --bin exp_client -- "${f}" --mode sim-generate

  echo "---------------------"
  echo "Aggregation:"
  echo "---------------------"
  cargo run --release --bin exp_client -- "${f}" --mode aggregate
done
