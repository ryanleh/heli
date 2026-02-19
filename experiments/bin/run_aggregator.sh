#!/usr/bin/env bash
set -euo pipefail

CONFIGS=(
  ../configs/simplified-1.json
  ../configs/simplified-32.json
  ../configs/simplified-128.json
)

export RUST_LOG=info
#export RUSTFLAGS="-C target-cpu=native"

# Run the aggregator
cargo run --release --bin exp_aggregator -- "${CONFIGS[0]}" --clear-db
