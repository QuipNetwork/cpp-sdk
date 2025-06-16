#!/bin/bash

# Default values
RPC_URL="http://localhost:8545"
CONTRACT_ADDRESS=""
CHAIN_ID=31337  # Default for local Hardhat

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --contract-address)
      CONTRACT_ADDRESS="$2"
      shift 2
      ;;
    --chain-id)
      CHAIN_ID="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if contract address is provided
if [ -z "$CONTRACT_ADDRESS" ]; then
  echo "Error: Contract address is required. Use --contract-address."
  exit 1
fi

# Run CLI commands and verify results
echo "Running E2E tests against $RPC_URL (Chain ID: $CHAIN_ID)"
echo "Contract Address: $CONTRACT_ADDRESS"

# Example: Call transfer command
echo "Testing transfer command..."
./build/quip-cli transfer \
  --rpc-url "$RPC_URL" \
  --contract-address "$CONTRACT_ADDRESS" \
  --pq-pubkey "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  --pq-sig "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  --to-address "0x1234567890123456789012345678901234567890" \
  --amount "1000000000000000000" \
  --private-key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Example: Call balance command
echo "Testing balance command..."
./build/quip-cli balance \
  --rpc-url "$RPC_URL" \
  --contract-address "$CONTRACT_ADDRESS" \
  --address "0x1234567890123456789012345678901234567890"

# Example: Call pq-owner command
echo "Testing pq-owner command..."
./build/quip-cli pq-owner \
  --rpc-url "$RPC_URL" \
  --contract-address "$CONTRACT_ADDRESS" \
  --address "0x1234567890123456789012345678901234567890"

echo "E2E tests completed." 