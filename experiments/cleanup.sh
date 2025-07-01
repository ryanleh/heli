#!/bin/bash

# HLAGG Cleanup Script
# Kills any leftover processes from experiments

echo "Cleaning up HLAGG processes..."

# Kill processes by name
pkill -f "target/release/decryptor" || echo "No decryptor processes found"
pkill -f "target/release/aggregator" || echo "No aggregator processes found"
pkill -f "target/release/client" || echo "No client processes found"

echo "Cleanup complete!" 