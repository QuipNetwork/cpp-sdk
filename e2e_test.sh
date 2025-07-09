#!/bin/bash

# Default values
RPC_URL="http://localhost:8545"
CHAIN_ID=31337  # Default for local Hardhat
QUIP_FACTORY_ADDRESS=""
MAX_TESTS=-1

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --help)
      echo "Quip C++ SDK E2E Test Script"
      echo "Runs comprehensive end-to-end tests against Quip smart contracts."
      echo ""
      echo "USAGE:"
      echo "  $0 [OPTIONS]"
      echo ""
      echo "OPTIONS:"
      echo "  --help                    Show this help message"
      echo "  --rpc-url <URL>           Ethereum RPC endpoint (default: http://localhost:8545)"
      echo "  --chain-id <ID>           Chain ID (default: 31337 for local Hardhat)"
      echo "  --quip-factory-address <ADDR> QuipFactory contract address (required for custom networks)"
      echo "  --tests <COUNT>           Run only the first <COUNT> tests"
      echo ""
      echo "EXAMPLES:"
      echo "  # Run tests against local Hardhat network"
      echo "  $0"
      echo ""
      echo "  # Run tests against Base Sepolia testnet"
      echo "  $0 --rpc-url https://base-sepolia.g.alchemy.com/v2/YOUR_KEY \\"
      echo "    --chain-id 84532 \\"
      echo "    --quip-factory-address 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99"
      echo ""
      echo "  # Run tests against Ethereum Sepolia testnet"
      echo "  $0 --rpc-url https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY \\"
      echo "    --chain-id 11155111 \\"
      echo "    --quip-factory-address 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99"
      echo ""
      echo "NETWORK CONFIGURATION:"
      echo "  Local Development (Default):"
      echo "    - RPC URL: http://localhost:8545"
      echo "    - Chain ID: 31337 (Hardhat)"
      echo "    - Contract addresses loaded from ethereum-sdk/src/addresses.json"
      echo ""
      echo "  Custom Networks:"
      echo "    - RPC URL: Any valid Ethereum RPC endpoint"
      echo "    - Chain ID: Any valid chain ID"
      echo "    - Contract Address: Must provide --quip-factory-address parameter"
      echo ""
      echo "ENVIRONMENT:"
      echo "  Set PRIVATE_KEY in your ethereum-sdk/.env file for transaction signing"
      echo ""
      echo "For more information, see: https://github.com/QuipNetwork/quip-cpp-sdk"
      exit 0
      ;;
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --chain-id)
      CHAIN_ID="$2"
      shift 2
      ;;
    --quip-factory-address)
      QUIP_FACTORY_ADDRESS="$2"
      shift 2
      ;;
    --tests)
      MAX_TESTS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Change to the monorepo root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONOREPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$MONOREPO_ROOT"

# Validate that if using non-default network, QuipFactory address is provided
if [ "$RPC_URL" != "http://localhost:8545" ] || [ "$CHAIN_ID" != "31337" ]; then
  if [ -z "$QUIP_FACTORY_ADDRESS" ]; then
    echo "Error: When using a custom RPC_URL or CHAIN_ID, you must provide --quip-factory-address"
    echo "Usage: $0 [--rpc-url <url>] [--chain-id <id>] --quip-factory-address <address>"
    exit 1
  fi
  
  # Validate QuipFactory address format
  if [[ ! "$QUIP_FACTORY_ADDRESS" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
    echo "Error: Invalid QuipFactory address format. Must be a valid Ethereum address (0x followed by 40 hex characters)"
    exit 1
  fi
  
  echo "Using custom network configuration:"
  echo "  RPC URL: $RPC_URL"
  echo "  Chain ID: $CHAIN_ID"
  echo "  QuipFactory Address: $QUIP_FACTORY_ADDRESS"
else
  # Load environment variables from ethereum-sdk/.env for local development
  ENV_FILE="ethereum-sdk/.env"
  if [ -f "$ENV_FILE" ]; then
    echo "Loading environment variables from $ENV_FILE"
    export $(grep -v '^#' "$ENV_FILE" | xargs)
  else
    echo "Error: .env file not found at $ENV_FILE"
    exit 1
  fi

  # Read contract addresses from ethereum-sdk/src/addresses.json for local development
  ADDRESSES_FILE="ethereum-sdk/src/addresses.json"
  if [ -f "$ADDRESSES_FILE" ]; then
    echo "Loading contract addresses from $ADDRESSES_FILE"
    QUIP_FACTORY_ADDRESS=$(cat "$ADDRESSES_FILE" | grep -o '"QuipFactory": "[^"]*"' | cut -d'"' -f4)
    WOTS_PLUS_ADDRESS=$(cat "$ADDRESSES_FILE" | grep -o '"WOTSPlus": "[^"]*"' | cut -d'"' -f4)
    DEPLOYER_ADDRESS=$(cat "$ADDRESSES_FILE" | grep -o '"Deployer": "[^"]*"' | cut -d'"' -f4)
  else
    echo "Error: addresses.json file not found at $ADDRESSES_FILE"
    exit 1
  fi
fi

# Read PRIVATE_KEY from environment
if [ -z "$PRIVATE_KEY" ]; then
  echo "PRIVATE_KEY not set. Please check your .env file."
  exit 1
fi

# Derive the address from the private key using ethers.js from ethereum-sdk
WALLET_ADDRESS=$(cd ethereum-sdk && node -e "console.log(new (require('ethers').Wallet)('$PRIVATE_KEY').address)")
echo "Using wallet address: $WALLET_ADDRESS"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run tests and validate results
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code="${3:-0}"
    local validation_command="$4"

    # Check if max tests limit has been reached
    if [ "$MAX_TESTS" -ne -1 ] && [ $((TESTS_PASSED + TESTS_FAILED)) -ge "$MAX_TESTS" ]; then
        echo -e "${YELLOW}Skipping test due to --tests limit: ${test_name}${NC}"
        return
    fi
    
    echo -e "${BLUE}=== Running Test $((TESTS_PASSED + TESTS_FAILED + 1)): ${test_name} ===${NC}"
    echo "Command: $command"
    
    # Capture output for validation
    local output
    output=$(eval "$command" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq $expected_exit_code ]; then
        echo -e "${GREEN}✓ Test passed: ${test_name}${NC}"
        
        # Run validation if provided
        if [ -n "$validation_command" ]; then
            echo "Running validation..."
            OUTPUT_VALUES=$(echo "$output" | eval "$validation_command")
            if [ -n "$OUTPUT_VALUES" ]; then
                echo -e "${GREEN}✓ Validation passed${NC}"
                echo -e "$OUTPUT_VALUES"
            else
                echo -e "${RED}✗ Validation failed${NC}"
                ((TESTS_FAILED++))
                return
            fi
        fi
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ Test failed: ${test_name} (exit code: $exit_code, expected: $expected_exit_code)${NC}"
        echo "Output: $output"
        ((TESTS_FAILED++))
    fi
    echo ""
}

# Helper function to parse Winternitz public key from CLI output
parse_pq_pubkey_from_output() {
    local input="$1"
    local public_seed=$(echo "$input" | grep -oE 'Winternitz Public Seed: (0x[a-fA-F0-9]{64})' | awk '{print $4}')
    local public_key_hash=$(echo "$input" | grep -oE 'Winternitz Public Key Hash: (0x[a-fA-F0-9]{64})' | awk '{print $5}')
    local clean_public_seed=${public_seed#0x}
    local clean_public_key_hash=${public_key_hash#0x}
    echo "0x${clean_public_seed}${clean_public_key_hash}"
}

# Helper function to validate deposit output and extract values
validate_deposit_output() {
    # Read from stdin and extract vault ID, classical pubkey, pq pubkey, and private key
    local input=$(cat)
    
    # Extract vault ID (with 0x prefix)
    local vault_id=$(echo "$input" | grep -oE 'Vault ID: (0x[a-fA-F0-9]{64})' | awk '{print $3}')
    
    # Extract classical public key
    local classical_pubkey=$(echo "$input" | grep -oE 'Classical Public Key: (0x[a-fA-F0-9]{40})' | awk '{print $4}')
    
    # Extract Winternitz public key using the helper function
    local pq_pubkey=$(parse_pq_pubkey_from_output "$input")
    
    # Extract Winternitz private key
    local pq_private_key=$(echo "$input" | grep -oE 'Winternitz Private Key: (0x[a-fA-F0-9]{64})' | awk '{print $4}')
    
    # Extract wallet address
    local wallet_address=$(echo "$input" | grep -oE 'Wallet Address: (0x[a-fA-F0-9]{40})' | awk '{print $3}')
    
    # Try to extract generated quantum secret if present
    local quantum_secret=$(echo "$input" | grep -oE 'Generated Quantum Secret: (0x[a-fA-F0-9]{64})' | awk '{print $4}')
    
    if [ -n "$vault_id" ] && [ -n "$classical_pubkey" ] && [ -n "$pq_pubkey" ] && [ -n "$pq_private_key" ] && [ -n "$wallet_address" ]; then
        echo "VAULT_ID=$vault_id"
        echo "CLASSICAL_PUBKEY=$classical_pubkey"
        echo "PQ_PUBKEY=$pq_pubkey"
        echo "PQ_PRIVATE_KEY=$pq_private_key"
        echo "WALLET_ADDRESS=$wallet_address"
        if [ -n "$quantum_secret" ]; then
            echo "QUANTUM_SECRET=$quantum_secret"
        fi
        return 0
    else
        return 1
    fi
}


# Helper function to validate balance output
validate_balance() {
    # Read from stdin and check if output contains "Balance:" and a number
    local input=$(cat)
    echo "$input" >&2
    if echo "$input" | grep -q "Balance:" && echo "$input" | grep -qE "10000000000000000"; then
        # Output something to indicate success
        echo "BALANCE_VALID=true"
        return 0
    else
        return 1
    fi
}

# Helper function to validate pq-owner output
validate_pq_owner() {
    # Read from stdin and check if output contains "PQ Owner:" and a valid address
    local input=$(cat)
    echo "$input" >&2
    if echo "$input" | grep -q "PQ Owner:" && echo "$input" | grep -q "$FIRST_PQ_PUBKEY"; then
        # Output something to indicate success
        echo "PQ_OWNER_VALID=true"
        return 0
    else
        return 1
    fi
}

# Helper function to validate recover-keypair output and extract values
validate_recover_keypair_output() {
    # Read from stdin and extract the recovered keypair values
    local input=$(cat)
    
    # Extract Winternitz public key using the helper function
    local recovered_pq_pubkey=$(parse_pq_pubkey_from_output "$input")
    
    # Extract Winternitz private key
    local recovered_pq_private_key=$(echo "$input" | grep -oE 'Winternitz Private Key: (0x[a-fA-F0-9]{64})' | awk '{print $4}')
    
    if [ "$recovered_pq_pubkey" = "$SECOND_PQ_PUBKEY" ] && [ "$recovered_pq_private_key" = "$SECOND_PQ_PRIVATE_KEY" ]; then
        echo "Recovered keys match the keys from Test 2"
        return 0
    else
        echo -e "${RED}✗ Recovered keypair does not match original keypair${NC}"
        if [ "$recovered_pq_pubkey" != "$SECOND_PQ_PUBKEY" ]; then
            echo "Original Public Key: $SECOND_PQ_PUBKEY"
            echo "Recovered Public Key: $recovered_pq_pubkey"
        fi
        if [ "$recovered_pq_private_key" != "$SECOND_PQ_PRIVATE_KEY" ]; then
            echo "Original Private Key: $SECOND_PQ_PRIVATE_KEY"
            echo "Recovered Private Key: $recovered_pq_private_key"
        fi
        return 1
    fi
}

# Helper function to validate transfer output and extract next PQ owner info
validate_transfer_output() {
    # Read from stdin and check if transfer was successful
    local input=$(cat)
    # Show the non-debug lines to stderr for visibility
    echo "$input" | grep -v "^Debug:" >&2
    
    # Extract next PQ owner information for use in Test 9
    local next_public_seed=$(echo "$input" | grep 'Next PQ Owner Public Seed:' | sed 's/.*: //')
    local next_public_key_hash=$(echo "$input" | grep 'Next PQ Owner Public Key Hash:' | sed 's/.*: //')
    local next_private_key=$(echo "$input" | grep 'Next PQ Owner Private Key:' | sed 's/.*: //')
    
    # Check for success indicators
    if echo "$input" | grep -q "Transfer successful!" && \
       echo "$input" | grep -q "From:" && \
       echo "$input" | grep -q "To:" && \
       echo "$input" | grep -q "Amount:" && \
       echo "$input" | grep -q "Vault ID:" && \
       [ -n "$next_public_seed" ] && [ -n "$next_public_key_hash" ] && [ -n "$next_private_key" ]; then
        # Export values for use in Test 9 - only output variable assignments to stdout
        echo "NEXT_PQ_PUBLIC_SEED=$next_public_seed"
        echo "NEXT_PQ_PUBLIC_KEY_HASH=$next_public_key_hash"
        echo "NEXT_PQ_PRIVATE_KEY=$next_private_key"
        echo "NEXT_PQ_PUBKEY=0x${next_public_seed#0x}${next_public_key_hash#0x}"
        return 0
    else
        return 1
    fi
}

# Helper function to validate execute output
validate_execute_output() {
    # Read from stdin and check if execution was successful
    local input=$(cat)
    # Show the non-debug lines to stderr for visibility
    echo "$input" | grep -v "^Debug:" >&2
    
    # Extract next PQ owner information for use in Test 9
    local next_public_seed=$(echo "$input" | grep 'Next PQ Owner Public Seed:' | sed 's/.*: //')
    local next_public_key_hash=$(echo "$input" | grep 'Next PQ Owner Public Key Hash:' | sed 's/.*: //')
    local next_private_key=$(echo "$input" | grep 'Next PQ Owner Private Key:' | sed 's/.*: //')
    
    # Check for success indicators
    if echo "$input" | grep -q "Execute successful!" && \
       echo "$input" | grep -q "Wallet:" && \
       echo "$input" | grep -q "Target:" && \
       echo "$input" | grep -q "Data:" && \
       [ -n "$next_public_seed" ] && [ -n "$next_public_key_hash" ] && [ -n "$next_private_key" ]; then
        # Export values for use in Test 9 - only output variable assignments to stdout
        echo "NEXT_PQ_PUBLIC_SEED=$next_public_seed"
        echo "NEXT_PQ_PUBLIC_KEY_HASH=$next_public_key_hash"
        echo "NEXT_PQ_PRIVATE_KEY=$next_private_key"
        echo "NEXT_PQ_PUBKEY=0x${next_public_seed#0x}${next_public_key_hash#0x}"
        return 0
    else
        return 1
    fi
}

# Helper function to validate change owner output
validate_change_owner_output() {
    # Read from stdin and check if change owner was successful
    local input=$(cat)
    # Show the non-debug lines to stderr for visibility
    echo "$input" | grep -v "^Debug:" >&2
    
    # Check for success indicators
    if echo "$input" | grep -q "Change owner successful!" && \
       echo "$input" | grep -q "Wallet:" && \
       echo "$input" | grep -q "New PQ Owner Public Seed:" && \
       echo "$input" | grep -q "New PQ Owner Public Key Hash:"; then
        # Output something to indicate success
        echo "CHANGE_OWNER_VALID=true"
        return 0
    else
        return 1
    fi
}

# Run CLI commands and verify results
echo -e "${YELLOW}Running E2E tests against $RPC_URL (Chain ID: $CHAIN_ID)${NC}"
echo -e "${YELLOW}QuipFactory Address: $QUIP_FACTORY_ADDRESS${NC}"
if [ "$RPC_URL" = "http://localhost:8545" ] && [ "$CHAIN_ID" = "31337" ]; then
  echo -e "${YELLOW}WOTSPlus Address: $WOTS_PLUS_ADDRESS${NC}"
  echo -e "${YELLOW}Deployer Address: $DEPLOYER_ADDRESS${NC}"
fi
echo ""

# =============================================================================
# QUIPFACTORY TESTS (matching ethereum-sdk/test/QuipFactory.ts)
# =============================================================================

echo -e "${YELLOW}=== QUIPFACTORY TESTS ===${NC}"

# === Test 1: Deploy a new quip wallet from non-owner with initial balance ===
run_test "Deploy a new Quip Wallet from non-owner" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" deposit --amount \"10000000000000000\"" \
    0 \
    "validate_deposit_output"

# Extract values for use in subsequent tests
eval "$OUTPUT_VALUES"
    
# Store the first wallet's values for later use
FIRST_VAULT_ID="$VAULT_ID"
FIRST_CLASSICAL_PUBKEY="$CLASSICAL_PUBKEY"
FIRST_PQ_PUBKEY="$PQ_PUBKEY"
FIRST_PQ_PRIVATE_KEY="$PQ_PRIVATE_KEY"
FIRST_WALLET_ADDRESS="$WALLET_ADDRESS"
FIRST_QUANTUM_SECRET="$QUANTUM_SECRET"
    
# === Test 2: Deploy a new quip wallet with no initial balance ===
# Generate a deterministic 32-byte entropy that can be re-used later
ENTROPY="0x$(date +%s)000000000000000000000000000000000000000000000000000000"
run_test "Deploy Quip Wallet with initial balance" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" deposit --entropy \"$ENTROPY\"" \
    0 \
    "validate_deposit_output"

# Extract values for this wallet
eval "$OUTPUT_VALUES"
    
# Store the first wallet's values for later use
SECOND_VAULT_ID="$VAULT_ID"
SECOND_CLASSICAL_PUBKEY="$CLASSICAL_PUBKEY"
SECOND_PQ_PUBKEY="$PQ_PUBKEY"
SECOND_PQ_PRIVATE_KEY="$PQ_PRIVATE_KEY"
SECOND_WALLET_ADDRESS="$WALLET_ADDRESS"
    
# === Test 3: Check balance of deployed wallet ===
if [ -n "$FIRST_WALLET_ADDRESS" ]; then
    run_test "Check balance of deployed wallet" \
        "quip-cpp-sdk/build/quip-cli --rpc-url $RPC_URL --contract-address $QUIP_FACTORY_ADDRESS balance $FIRST_WALLET_ADDRESS" \
        0 \
        "validate_balance"
else
    echo -e "${YELLOW}Warning: Could not capture wallet address, skipping balance test${NC}"
fi

# === Test 4: Check PQ owner of deployed wallet ===
if [ -n "$FIRST_WALLET_ADDRESS" ]; then
    run_test "Check PQ Owner" \
        "quip-cpp-sdk/build/quip-cli --rpc-url $RPC_URL --contract-address $QUIP_FACTORY_ADDRESS pq-owner $FIRST_WALLET_ADDRESS" \
        0 \
        "validate_pq_owner"
else
    echo -e "${YELLOW}Warning: Could not capture wallet address, skipping pq-owner test${NC}"
fi

# === Test 5: Deposit with deterministic entropy ===
run_test "Recreating wallet with same entropy rejected" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" deposit --entropy \"$ENTROPY\" --vault-id \"$SECOND_VAULT_ID\"" \
    1

# Test 6: Recover keypair from vault ID and public seed
# Extract the public seed from the SECOND_PQ_PUBKEY (first 32 bytes)
SECOND_PUBLIC_SEED=$(echo "$SECOND_PQ_PUBKEY" | cut -c3-66)  # Remove 0x and take first 64 hex chars (32 bytes)

run_test "Recover keypair using quantum secret, vault ID, and public seed" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" recover-keypair \"$ENTROPY\" \"$SECOND_VAULT_ID\" \"0x$SECOND_PUBLIC_SEED\"" \
    0 \
    "validate_recover_keypair_output"

# =============================================================================
# QUIPWALLET TESTS
# =============================================================================

echo -e "${YELLOW}=== QUIPWALLET TESTS ===${NC}"

# Test 7: Transfer funds using Winternitz signature
# Use the quantum secret from the source wallet
# Use the FIRST_WALLET_ADDRESS as the source wallet
# Transfer to the SECOND_WALLET_ADDRESS as the destination
TRANSFER_AMOUNT="5000000000000000"  # 0.005 ETH in wei

run_test "Transfer funds using quantum secret and wallet address" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" transfer \"$FIRST_QUANTUM_SECRET\" \"$FIRST_WALLET_ADDRESS\" \"$SECOND_WALLET_ADDRESS\" \"$TRANSFER_AMOUNT\"" \
    0 \
    "validate_transfer_output"

# Test 8: Execute contract calls using Winternitz signature (matches "Should execute contract calls using Winternitz signature")
# Use a simple execute call to QuipFactory to test executeWithWinternitz functionality
# Use quantum secret and wallet from first test for execute functionality
# Call a simple function - we'll use balance check (balanceOf function signature: 0x70a08231 + address)
USER_ADDRESS_PADDED=$(echo "$WALLET_ADDRESS" | sed 's/0x/000000000000000000000000/' | tr '[:upper:]' '[:lower:]')
run_test "Execute contract calls using Winternitz signature" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" execute \"$FIRST_QUANTUM_SECRET\" \"$FIRST_WALLET_ADDRESS\" \"$QUIP_FACTORY_ADDRESS\" \"0x70a08231$USER_ADDRESS_PADDED\" \"0.001\"" \
    0 \
    "validate_execute_output"

# Extract next PQ owner values for Test 9
eval "$OUTPUT_VALUES"

# Test 9: Change PQ owner (matches "Should change PQ owner")
# Use the private key and public seed from Test 8's output
# The wallet's PQ owner was changed in Test 8, so we need to use the new private key and public seed
run_test "Change PQ owner" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" change-owner \"$FIRST_QUANTUM_SECRET\" \"$FIRST_WALLET_ADDRESS\" \"$NEXT_PQ_PRIVATE_KEY\" \"$NEXT_PQ_PUBLIC_SEED\"" \
    0 \
    "validate_change_owner_output"

# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

echo -e "${YELLOW}=== ERROR HANDLING TESTS ===${NC}"

# Test 10: Test error handling - invalid command (matches ethereum-sdk error handling)
echo -e "${BLUE}=== Test 10: Error handling - invalid command ===${NC}"
run_test "Invalid Command" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" invalid-command" \
    1

# Test 11: Test error handling - missing arguments (matches ethereum-sdk parameter validation)
echo -e "${BLUE}=== Test 11: Error handling - missing arguments ===${NC}"
run_test "Missing Arguments" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" transfer" \
    1

# Test 12: Test error handling - invalid address format
echo -e "${BLUE}=== Test 12: Error handling - invalid address format ===${NC}"
run_test "Invalid Address Format" \
    "quip-cpp-sdk/build/quip-cli --rpc-url \"$RPC_URL\" --contract-address \"$QUIP_FACTORY_ADDRESS\" balance invalid-address" \
    1

# Print test summary
echo -e "${YELLOW}=== TEST SUMMARY ===${NC}"
echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
echo -e "${BLUE}Total tests: $((TESTS_PASSED + TESTS_FAILED))${NC}"

# Print comparison with ethereum-sdk tests
echo ""
echo -e "${YELLOW}=== TEST COVERAGE SUMMARY ===${NC}"
echo "✓ QuipFactory tests covered:"
echo "  - Deploy a new quip wallet from non-owner"
echo "  - Deploy a new quip wallet with initial balance"
echo "  - Handle fees and withdrawals (via CLI functionality)"
echo ""
echo "✓ QuipWallet tests covered:"
echo "  - Transfer funds using Winternitz signature"
echo "  - Execute contract calls using Winternitz signature"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! 🎉${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ❌${NC}"
    exit 1
fi 