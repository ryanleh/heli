#!/usr/bin/env bash
set -euo pipefail

CONFIGS=(
  ../configs/full-1.json
  ../configs/full-32.json
  ../configs/full-128.json
)

export RUST_LOG=info
export RUSTFLAGS="-C target-cpu=native"

# Run the aggregator
cargo run --release --bin exp_aggregator -- "${CONFIGS[0]}" --clear-db
