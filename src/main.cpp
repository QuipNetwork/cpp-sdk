#include "cli.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

void printHelp(const char *program_name) {
  std::cout << "Quip C++ SDK CLI Tool\n";
  std::cout << "A command-line interface for interacting with Quip smart "
               "contracts using Winternitz signatures.\n\n";

  std::cout << "USAGE:\n";
  std::cout << "  " << program_name << " [OPTIONS] <COMMAND> [ARGS...]\n\n";

  std::cout << "OPTIONS:\n";
  std::cout << "  --help                    Show this help message\n";
  std::cout << "  --rpc-url <URL>           Ethereum RPC endpoint (default: "
               "http://localhost:8545)\n";
  std::cout << "  --contract-address <ADDR> QuipFactory contract address "
               "(required for custom networks)\n\n";

  std::cout << "COMMANDS:\n";
  std::cout << "  deposit [--amount <amount>] [--entropy <entropy>]"
            << std::endl;
  std::cout
      << "    --amount: Amount in wei to deposit (default: 10000000000000000)"
      << std::endl;
  std::cout << "    --entropy: Optional hex string for deterministic vault ID"
            << std::endl;
  std::cout << "    Deploy a new Quip wallet using Winternitz signatures\n";
  std::cout << "    - Uses PRIVATE_KEY environment variable for classical "
               "public key derivation\n";
  std::cout
      << "    - Generates Winternitz keypair using hashsigs-cpp library\n";
  std::cout << "    - Outputs vault ID, classical public key, Winternitz "
               "public key, and wallet address\n\n";

  std::cout
      << "  transfer <pubkey> <sig> <to_address> <amount> <private_key>\n";
  std::cout
      << "    Transfer funds from a Quip wallet using Winternitz signature\n";
  std::cout << "    - pubkey: 32-byte public key in hex format (0x...)\n";
  std::cout << "    - sig: Winternitz signature in hex format (0x...)\n";
  std::cout << "    - to_address: Destination Ethereum address (0x...)\n";
  std::cout << "    - amount: Transfer amount in wei\n";
  std::cout << "    - private_key: Private key for transaction signing\n\n";

  std::cout
      << "  execute <pubkey> <sig> <target_address> <opdata> <private_key>\n";
  std::cout << "    Execute a contract call from a Quip wallet using "
               "Winternitz signature\n";
  std::cout << "    - pubkey: 32-byte public key in hex format (0x...)\n";
  std::cout << "    - sig: Winternitz signature in hex format (0x...)\n";
  std::cout << "    - target_address: Target contract address (0x...)\n";
  std::cout << "    - opdata: Operation data in hex format (0x...)\n";
  std::cout << "    - private_key: Private key for transaction signing\n\n";

  std::cout << "  change-owner <pubkey> <sig> <private_key>\n";
  std::cout << "    Change the PQ owner of a Quip wallet using Winternitz "
               "signature\n";
  std::cout << "    - pubkey: 32-byte public key in hex format (0x...)\n";
  std::cout << "    - sig: Winternitz signature in hex format (0x...)\n";
  std::cout << "    - private_key: Private key for transaction signing\n\n";

  std::cout << "  balance <address>\n";
  std::cout << "    Get the balance of a Quip wallet\n";
  std::cout << "    - address: Quip wallet address (0x...)\n\n";

  std::cout << "  pq-owner <address>\n";
  std::cout << "    Get the PQ owner of a Quip wallet\n";
  std::cout << "    - address: Quip wallet address (0x...)\n\n";

  std::cout << "EXAMPLES:\n";
  std::cout << "  # Deploy a new wallet on local Hardhat network\n";
  std::cout << "  " << program_name << " --rpc-url http://localhost:8545 \\\n";
  std::cout << "    --contract-address "
               "0x6485c24b7f91e951a739cf7Aece1696118cCf467 \\\n";
  std::cout << "    deposit\n\n";

  std::cout << "  # Deploy a new wallet with deterministic vault ID and custom "
               "amount\n";
  std::cout << "  " << program_name << " --rpc-url http://localhost:8545 \\\n";
  std::cout << "    --contract-address "
               "0x6485c24b7f91e951a739cf7Aece1696118cCf467 \\\n";
  std::cout << "    deposit --amount 50000000000000000 --entropy "
               "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc"
               "def\n\n";

  std::cout << "  # Transfer funds on Base Sepolia testnet\n";
  std::cout << "  " << program_name
            << " --rpc-url https://base-sepolia.g.alchemy.com/v2/YOUR_KEY \\\n";
  std::cout << "    --contract-address "
               "0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99 \\\n";
  std::cout << "    transfer 0x1234... 0xabcd... 0x9876... 1000000000000000000 "
               "0x5678...\n\n";

  std::cout << "  # Check wallet balance\n";
  std::cout << "  " << program_name << " --rpc-url http://localhost:8545 \\\n";
  std::cout << "    --contract-address "
               "0x6485c24b7f91e951a739cf7Aece1696118cCf467 \\\n";
  std::cout << "    balance 0x1234567890123456789012345678901234567890\n\n";

  std::cout << "NETWORK CONFIGURATION:\n";
  std::cout << "  Local Development (Default):\n";
  std::cout << "    - RPC URL: http://localhost:8545\n";
  std::cout << "    - Chain ID: 31337 (Hardhat)\n";
  std::cout << "    - Contract addresses loaded from "
               "ethereum-sdk/src/addresses.json\n\n";

  std::cout << "  Custom Networks:\n";
  std::cout << "    - RPC URL: Any valid Ethereum RPC endpoint\n";
  std::cout << "    - Chain ID: Any valid chain ID\n";
  std::cout << "    - Contract Address: Must provide --contract-address "
               "parameter\n\n";

  std::cout << "ENVIRONMENT:\n";
  std::cout
      << "  Set PRIVATE_KEY in your .env file for transaction signing\n\n";

  std::cout << "For more information, see: "
               "https://github.com/QuipNetwork/quip-cpp-sdk\n";
}

// Helper: load environment variables from a .env file
void loadEnvFromFile(const std::string &env_path) {
  std::ifstream env_file(env_path);
  if (!env_file.is_open()) {
    std::cerr << "Warning: .env file not found at " << env_path << std::endl;
    return;
  }
  std::string line;
  while (std::getline(env_file, line)) {
    // Ignore comments and empty lines
    if (line.empty() || line[0] == '#')
      continue;
    size_t eq_pos = line.find('=');
    if (eq_pos == std::string::npos)
      continue;
    std::string key = line.substr(0, eq_pos);
    std::string value = line.substr(eq_pos + 1);
    // Remove possible trailing % or whitespace
    if (!value.empty() && value.back() == '%')
      value.pop_back();
    // Remove leading/trailing whitespace
    key.erase(0, key.find_first_not_of(" \t\n\r"));
    key.erase(key.find_last_not_of(" \t\n\r") + 1);
    value.erase(0, value.find_first_not_of(" \t\n\r"));
    value.erase(value.find_last_not_of(" \t\n\r") + 1);
    setenv(key.c_str(), value.c_str(), 0); // do not overwrite existing
  }
}

int main(int argc, char *argv[]) {
  // If PRIVATE_KEY is not set, try to load from ./ethereum-sdk/.env
  if (std::getenv("PRIVATE_KEY") == nullptr) {
    loadEnvFromFile("./ethereum-sdk/.env");
  }
  if (std::getenv("PRIVATE_KEY") == nullptr) {
    std::cerr << "Error: PRIVATE_KEY environment variable not set.\n"
                 "Please create ./ethereum-sdk/.env with a PRIVATE_KEY entry, "
                 "or export PRIVATE_KEY manually."
              << std::endl;
    return 1;
  }

  if (argc < 2) {
    std::cerr << "Usage: " << argv[0]
              << " [--rpc-url <url>] [--contract-address <address>] <command> "
                 "[args...]"
              << std::endl;
    std::cerr << "Default RPC URL: http://localhost:8545" << std::endl;
    std::cerr << "Use --help for more information" << std::endl;
    return 1;
  }

  // Check for help flag first
  if (std::string(argv[1]) == "--help") {
    printHelp(argv[0]);
    return 0;
  }

  // Default values
  std::string rpc_url = "http://localhost:8545";
  std::string contract_address = "";
  std::vector<std::string> command_args;

  // Parse command line arguments
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "--rpc-url" && i + 1 < argc) {
      rpc_url = argv[++i];
    } else if (arg == "--contract-address" && i + 1 < argc) {
      contract_address = argv[++i];
    } else if (arg == "--help") {
      printHelp(argv[0]);
      return 0;
    } else if (arg.substr(0, 2) == "--") {
      std::cerr << "Unknown option: " << arg << std::endl;
      std::cerr << "Use --help for usage information" << std::endl;
      return 1;
    } else {
      // Everything else is part of the command
      for (int j = i; j < argc; ++j) {
        command_args.push_back(argv[j]);
      }
      break;
    }
  }

  if (command_args.empty()) {
    std::cerr << "No command specified" << std::endl;
    std::cerr << "Use --help for usage information" << std::endl;
    return 1;
  }

  try {
    quip::CLI cli(rpc_url, contract_address);
    return cli.execute(command_args) ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}