# Quip C++ SDK

A C++ SDK for interacting with Quip smart contracts on Ethereum networks.

## Features

- **QuipFactory Integration**: Deploy and manage Quip wallets
- **QuipWallet Operations**: Transfer funds, execute contracts, and manage ownership
- **Winternitz Signature Support**: Post-quantum secure signatures
- **Multi-Network Support**: Works with local Hardhat and custom networks
- **CLI Interface**: Command-line tool for testing and automation

## Building

1. Clone the repository:

```bash
git clone https://github.com/QuipNetwork/quip-cpp-sdk.git
cd quip-cpp-sdk
```

1.  Run the build script:

```bash
./build.sh
```

This will build both the CLI tool and run the test suite.

## Usage

### CLI Tool

The CLI tool supports both local development and custom network configurations.

#### Getting Help

```bash
# Show comprehensive help and usage information
./build/quip-cli --help
```

#### Local Development (Default)

For local development with Hardhat:

./build.sh

## Running the CLI

Basic usage:

```bash
./build/quip-cli <command> [args]
```

Commands:

- `deposit [entropy]` - Deploy a new Quip wallet using Winternitz signatures
- `transfer <pq_pubkey> <pq_sig> <to_address> <amount> <private_key>`
- `execute <pq_pubkey> <pq_sig> <target_address> <opdata> <private_key>`
- `change-owner <pq_pubkey> <pq_sig> <private_key>`
- `balance <address>`
- `pq-owner <address>`

To generate post-quantum keypairs and signatures, please use the [`hashsigs-cpp`](https://github.com/QuipNetwork/hashsigs-cpp) library.

## End-to-End (E2E) Testing

To run E2E tests against a real blockchain (local devnet, testnet, or mainnet), follow these steps:

1. **Deploy Contracts on a Local Devnet or Testnet**

   Use the existing [`ethereum-sdk`](https://github.com/QuipNetwork/ethereum-sdk) project to deploy the QuipFactory and QuipWallet contracts on localhost or use a sepolia contract on eg [mainnet](https://sepolia.etherscan.io/address/0x4a5a444f3b12342dc50e34f562dffbf0152cbb99#code) or [base](https://sepolia.basescan.org/address/0x4a5a444f3b12342dc50e34f562dffbf0152cbb99#code). For example, from the ethereum-sdk directory:

   ```bash
   cd ../ethereum-sdk
   npx hardhat node & INITIAL_OWNER=$PUBLIC_ADDRESS_YOU_CONTROL npx hardhat run scripts/deploy.ts --network hardhat
   ```

   This will deploy the contracts and output their addresses, but your local addresses will not match the default addresses and the transaction will unwind.

   Get your local Deployer, WOTSPlus, and QuipFactory addresses and write the deployer address to your ethereum-sdk .env file, then write all three contract addresses to `ethereum-sdk/src/addresses.json` and run the command again.

   You can check that your contracts are deployed by running `npx hardhat console` and using the following command with `"Deployer" | "WOTSPlus" | "QuipFactory"` as the `contractName` and the associated contract address as `contractAddress`

   ```typescript
   await ethers.getContractAt(`${contractName}`, `${contractAddress}`);
   ```

2. **Run the E2E Test Script**

   Use the provided bash script to run the CLI against the deployed contracts:

```bash
# Show E2E test script help
./e2e_test.sh --help

# Run all tests against local Hardhat network
./e2e_test.sh

# Run specific CLI commands
./build/quip-cli --rpc-url "https://base-sepolia.g.alchemy.com/v2/your_api_key_here" --contract-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99" deposit <pubkey> <sig> <private_key>
```

#### Custom Networks

When using a custom RPC_URL or CHAIN_ID, you **must** provide a QuipFactory contract address:

```bash
# Test against Sepolia testnet
./e2e_test.sh \
  --rpc-url "https://eth-sepolia.g.alchemy.com/v2/your_api_key_here" \
  --chain-id 11155111 \
  --quip-factory-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99"

# Test against Base mainnet
./e2e_test.sh \
  --rpc-url "https://mainnet.base.org" \
  --chain-id 8453 \
  --quip-factory-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99"
```

#### CLI Commands

```bash
# Deploy a new Quip wallet
./build/quip-cli --rpc-url <url> --contract-address <factory_address> deposit <pubkey> <sig> <private_key>

# Transfer funds
./build/quip-cli --rpc-url <url> --contract-address <factory_address> transfer <pubkey> <sig> <to_address> <amount> <private_key>

# Execute contract call
./build/quip-cli --rpc-url <url> --contract-address <factory_address> execute <pubkey> <sig> <target_address> <opdata> <private_key>

# Change PQ owner
./build/quip-cli --rpc-url <url> --contract-address <factory_address> change-owner <pubkey> <sig> <private_key>

# Check wallet balance
./build/quip-cli --rpc-url <url> --contract-address <factory_address> balance <address>

# Check PQ owner
./build/quip-cli --rpc-url <url> --contract-address <factory_address> pq-owner <address>
```

## Configuration

### Environment Variables

Create a `.env` based on the `.env.example` file in the [`ethereum-sdk`](https://github.com/QuipNetwork/ethereum-sdk) directory.

### Contract Addresses

For local development, contract addresses are automatically loaded from `ethereum-sdk/src/addresses.json`.

For custom networks, you must provide the QuipFactory contract address using the `--quip-factory-address` parameter.

## Testing

### Unit Tests

```bash
cd build && ./quip-cli-tests
```

### End-to-End Tests

```bash
# Show E2E test help
./e2e_test.sh --help

# Local development
./e2e_test.sh

# Custom network
./e2e_test.sh --rpc-url <url> --chain-id <id> --quip-factory-address <address>
```

## Network Requirements

### Local Development

- **RPC URL**: `http://localhost:8545` (default)
- **Chain ID**: `31337` (default)
- **Contract Addresses**: Automatically loaded from ethereum-sdk

### Custom Networks

- **RPC URL**: Any valid Ethereum RPC endpoint
- **Chain ID**: Any valid chain ID
- **QuipFactory Address**: **Required** - Must be a valid Ethereum address (0x followed by 40 hex characters)

## Error Handling

The CLI validates:

- QuipFactory address format (must be valid Ethereum address)
- Required parameters for custom networks
- Command syntax and argument counts
- Network connectivity

## Examples

### Complete Workflow

```bash
# 1. Deploy a new wallet
./build/quip-cli --rpc-url "https://base-sepolia.g.alchemy.com/v2/your_api_key_here" --contract-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99" deposit <pubkey> <sig> <private_key>

# 2. Transfer funds
./build/quip-cli --rpc-url "https://base-sepolia.g.alchemy.com/v2/your_api_key_here" --contract-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99" transfer <pubkey> <sig> "0x1234..." "1000000000000000000" <private_key>

# 3. Execute contract call
./build/quip-cli --rpc-url "https://base-sepolia.g.alchemy.com/v2/your_api_key_here" --contract-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99" execute <pubkey> <sig> "0x5678..." "0x12345678" <private_key>

# 4. Change owner
./build/quip-cli --rpc-url "https://base-sepolia.g.alchemy.com/v2/your_api_key_here" --contract-address "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99" change-owner <pubkey> <sig> <private_key>
```

## Dependencies

- CMake 3.10+
- C++17 compiler
- libcurl
- nlohmann/json
- Google Test (for testing)
- OpenSSL 3.0+

## License

AGPL-3.0, see COPYING
