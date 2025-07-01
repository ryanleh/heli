#!/bin/bash

# Usage: ./run_experiment.sh <party> <config_file>
# Parties: decryptor, aggregator, client

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Check arguments
if [ $# -lt 2 ]; then
  print_error "Usage: $0 <party> <config_file>"
  print_error "Parties: decryptor, aggregator, client"
  print_error "Example: $0 decryptor experiments/configs/config.toml"
  exit 1
fi

PARTY="$1"
CONFIG_FILE="$2"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  print_error "Config file not found: $CONFIG_FILE"
  exit 1
fi

print_status "Starting $PARTY with config: $CONFIG_FILE"

# Run the specified component
case $PARTY in
"decryptor")
  print_status "Starting decryptor..."
  cargo run --release --bin decryptor -- --config "$CONFIG_FILE"
  ;;
"aggregator")
  print_status "Starting aggregator..."
  cargo run --release --bin aggregator -- --config "$CONFIG_FILE"
  ;;
"client")
  print_status "Starting client..."
  ./target/release/client --config "$CONFIG_FILE"
  ;;
*)
  print_error "Unknown party: $PARTY"
  print_error "Valid parties: decryptor, aggregator, client"
  exit 1
  ;;
esac

print_success "$PARTY completed!"
