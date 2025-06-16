# Quip CLI

A command-line interface tool for interacting with Quip smart contracts using Winternitz signatures.

## Dependencies

- CMake 3.10 or higher
- C++17 compatible compiler
- libcurl
- nlohmann_json
- Google Test (for running tests)
- hashsigs-cpp library

## Building

1. Clone the repository:

```bash
git clone https://github.com/yourusername/quip-cli.git
cd quip-cli
```

2. Create a build directory and run CMake:

```bash
mkdir build
cd build
cmake ..
```

3. Build the project:

```bash
make
```

Run the build script:

```bash
./build.sh
```

## Running the CLI

Basic usage:

```bash
./build/quip-cli <command> [args]
```

Commands:

- `deposit <pq_pubkey> <pq_sig> <private_key>`
- `transfer <pq_pubkey> <pq_sig> <to_address> <amount> <private_key>`
- `execute <pq_pubkey> <pq_sig> <target_address> <opdata> <private_key>`
- `change-owner <pq_pubkey> <pq_sig> <private_key>`
- `balance <address>`
- `pq-owner <address>`

## End-to-End (E2E) Testing

To run E2E tests against a real blockchain (local devnet, testnet, or mainnet), follow these steps:

1. **Deploy Contracts on a Local Devnet or Testnet**

   Use the existing ethereum-sdk project to deploy the QuipFactory and QuipWallet contracts. For example, from the ethereum-sdk directory:

   ```bash
   cd ../ethereum-sdk
   npx hardhat node
   npx hardhat run scripts/deploy.ts --network localhost
   ```

   This will deploy the contracts and output their addresses.

2. **Run the E2E Test Script**

   Use the provided bash script to run the CLI against the deployed contracts:

   ```bash
   cd ../quip-cli
   ./e2e_test.sh --rpc-url http://localhost:8545 --contract-address <DEPLOYED_CONTRACT_ADDRESS>
   ```

   Options:

   - `--rpc-url`: URL of the Ethereum node (default: http://localhost:8545)
   - `--contract-address`: Address of the deployed QuipWallet contract
   - `--chain-id`: Chain ID (default: 31337 for local Hardhat)

   Example for a testnet:

   ```bash
   ./e2e_test.sh --rpc-url https://goerli.infura.io/v3/YOUR_INFURA_KEY --contract-address <DEPLOYED_CONTRACT_ADDRESS> --chain-id 5
   ```

3. **Verify Results**

   The script will call the CLI commands and verify the on-chain state (balances, PQ owner, events) using ethers.js.

## E2E Test Script

The `e2e_test.sh` script orchestrates the CLI calls and verifies the results. It uses the existing ethereum-sdk deployment logic and calls the CLI with the correct arguments.

Example usage:

```bash
./e2e_test.sh --rpc-url http://localhost:8545 --contract-address 0x1234567890123456789012345678901234567890
```

## Notes

- Ensure the ethereum-sdk project is built and the contracts are deployed before running the E2E tests.
- The E2E tests require a running Ethereum node (local or remote).
- The script assumes the CLI binary is located at `./build/quip-cli`.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
