#include "../include/cli.hpp"
#include "../include/common.hpp"
#include "keccak.h"
#include "wotsplus.hpp"
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace quip {

// Keccak-256 hash function implementation for hashsigs-cpp
static std::array<uint8_t, 32> keccak256(const std::vector<uint8_t> &data) {
  Keccak keccak(Keccak::Keccak256);
  std::string hash = keccak(data.data(), data.size());

  std::array<uint8_t, 32> result;
  for (size_t i = 0; i < 32; ++i) {
    std::string byte_str = hash.substr(i * 2, 2);
    result[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
  }
  return result;
}

// Helper: parse a hex string into a PublicKey (array<uint8_t, 32>)
static PublicKey parsePublicKeyFromHex(const std::string &hex) {
  std::vector<uint8_t> bytes = fromHex(hex);
  if (bytes.size() != 32)
    throw std::runtime_error("Invalid pubkey length");
  PublicKey arr;
  std::copy(bytes.begin(), bytes.end(), arr.begin());
  return arr;
}

// Helper: parse a hex string into a WinternitzAddress (64-byte format: 32-byte
// publicSeed + 32-byte publicKeyHash)
static WinternitzAddress parseWinternitzAddressFromHex(const std::string &hex) {
  std::vector<uint8_t> bytes = fromHex(hex);
  if (bytes.size() != 64)
    throw std::runtime_error(
        "Invalid Winternitz address length: expected 64 bytes, got " +
        std::to_string(bytes.size()));

  WinternitzAddress address;
  std::copy(bytes.begin(), bytes.begin() + 32, address.publicSeed.begin());
  std::copy(bytes.begin() + 32, bytes.end(), address.publicKeyHash.begin());
  return address;
}

// Helper: parse a hex string into a Signature (vector<array<uint8_t, 32>>)
static Signature parseSignatureFromHex(const std::string &hex) {
  std::vector<uint8_t> bytes = fromHex(hex);
  if (bytes.size() % 32 != 0)
    throw std::runtime_error("Invalid signature length");
  Signature sig(bytes.size() / 32);
  for (size_t i = 0; i < sig.size(); ++i) {
    std::copy_n(bytes.begin() + i * 32, 32, sig[i].begin());
  }
  return sig;
}

// Helper: derive classical public key from private key using ethers.js
static Address deriveClassicalPublicKey(const PrivateKey &private_key) {
  // Use the same approach as e2e_test.sh - call ethers.js from ethereum-sdk
  std::string command = "cd ./ethereum-sdk && node -e \"console.log(new "
                        "(require('ethers').Wallet)('" +
                        private_key + "').address)\"";

  FILE *pipe = popen(command.c_str(), "r");
  if (!pipe) {
    throw std::runtime_error("Failed to execute ethers.js command");
  }

  std::string result;
  char buffer[128];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }

  int status = pclose(pipe);
  if (status != 0) {
    throw std::runtime_error("ethers.js command failed: " + result);
  }

  // Remove newline and return the address
  if (!result.empty() && result[result.length() - 1] == '\n') {
    result.erase(result.length() - 1);
  }

  return result;
}

// Helper: generate Winternitz keypair using hashsigs-cpp
static std::pair<WinternitzAddress, std::array<uint8_t, 32>>
generateWinternitzKeypair(const std::string &entropy = "") {
  // Create WOTSPlus instance with Keccak-256
  hashsigs::WOTSPlus wots(keccak256);

  std::array<uint8_t, 32> private_key;

  if (entropy.empty()) {
    // Generate random private key
    for (int i = 0; i < 32; ++i) {
      private_key[i] = static_cast<uint8_t>(rand() % 256);
    }
  } else {
    // Use provided entropy to generate deterministic private key
    std::vector<uint8_t> entropyBytes = fromHex(entropy);
    if (entropyBytes.size() < 32) {
      // Pad with zeros if entropy is too short
      entropyBytes.resize(32, 0);
    } else if (entropyBytes.size() > 32) {
      // Truncate if entropy is too long
      entropyBytes.resize(32);
    }
    std::copy(entropyBytes.begin(), entropyBytes.end(), private_key.begin());
  }

  // Generate public key using hashsigs-cpp
  hashsigs::PublicKey public_key = wots.get_public_key(private_key);

  // Convert to our WinternitzAddress format
  WinternitzAddress pqAddress;
  pqAddress.publicSeed = public_key.get_public_seed();
  pqAddress.publicKeyHash = public_key.get_public_key_hash();

  return {pqAddress, private_key};
}

CLI::CLI(const std::string &rpc_url, const std::string &contract_address)
    : rpc_url_(rpc_url), contract_address_(contract_address) {
  factory_ =
      std::make_unique<QuipFactory>(rpc_url, getContractAddress("QuipFactory"));
}

CLI::~CLI() = default;

bool CLI::execute(const std::vector<std::string> &args) {
  if (args.empty()) {
    printUsage();
    return false;
  }

  const std::string &command = args[0];
  std::vector<std::string> command_args(args.begin() + 1, args.end());

  if (command == "deposit") {
    return handleDeposit(command_args);
  } else if (command == "transfer") {
    return handleTransfer(command_args);
  } else if (command == "execute") {
    return handleExecute(command_args);
  } else if (command == "change-owner") {
    return handleChangeOwner(command_args);
  } else if (command == "balance") {
    return handleGetBalance(command_args);
  } else if (command == "pq-owner") {
    return handleGetPqOwner(command_args);
  } else {
    std::cerr << "Unknown command: " << command << std::endl;
    printUsage();
    return false;
  }
}

bool CLI::handleDeposit(const std::vector<std::string> &args) {
  Amount amount = 0;
  std::string entropy = "";

  // Parse flags
  for (size_t i = 0; i < args.size(); ++i) {
    if (args[i] == "--amount" && i + 1 < args.size()) {
      amount = std::stoull(args[++i]);
    } else if (args[i] == "--entropy" && i + 1 < args.size()) {
      entropy = args[++i];
    } else {
      std::cerr << "Unknown or incomplete flag: " << args[i] << std::endl;
      std::cerr << "Usage: deposit [--amount <amount>] [--entropy <entropy>]"
                << std::endl;
      return false;
    }
  }

  try {
    // Initialize random seed if needed
    static bool seeded = false;
    if (!seeded) {
      std::srand(std::time(nullptr));
      seeded = true;
    }

    // Generate vault ID
    VaultId vaultId = generateVaultId(entropy);

    // Get private key from environment (should be loaded by e2e_test.sh)
    const char *env_private_key = std::getenv("PRIVATE_KEY");
    if (!env_private_key) {
      std::cerr << "Error: PRIVATE_KEY environment variable not set"
                << std::endl;
      std::cerr << "Make sure to run this from e2e_test.sh or set PRIVATE_KEY "
                   "in ethereum-sdk/.env"
                << std::endl;
      return false;
    }
    PrivateKey private_key = env_private_key;

    // Derive classical public key from private key using ethers.js
    Address classical_pubkey = deriveClassicalPublicKey(private_key);

    // Generate Winternitz keypair using hashsigs-cpp
    auto [winternitz_address, winternitz_private_key] =
        generateWinternitzKeypair(entropy);

    // Call the factory to create the wallet
    Address wallet_address = factory_->depositToWinternitz(
        vaultId, classical_pubkey, winternitz_address, private_key, amount);

    if (!wallet_address.empty() &&
        wallet_address != "0x0000000000000000000000000000000000000000") {
      std::cout << "Vault ID: " << toHex(vaultId) << std::endl;
      std::cout << "Classical Public Key: " << classical_pubkey << std::endl;
      std::cout << "Winternitz Public Seed: "
                << toHex(winternitz_address.publicSeed) << std::endl;
      std::cout << "Winternitz Public Key Hash: "
                << toHex(winternitz_address.publicKeyHash) << std::endl;
      std::cout << "Wallet Address: " << wallet_address << std::endl;
      std::cout << "Winternitz Private Key: " << toHex(winternitz_private_key)
                << std::endl;
      return true;
    } else {
      std::cerr << "Error: Failed to create wallet" << std::endl;
      return false;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleTransfer(const std::vector<std::string> &args) {
  if (args.size() != 4 && args.size() != 5) {
    std::cerr << "Usage: transfer <winternitz_address> <pq_sig> <to_address> "
                 "<amount> [wallet_owner_private_key]"
              << std::endl;
    std::cerr << "  winternitz_address: 64-byte Winternitz address in hex "
                 "format (0x...)"
              << std::endl;
    std::cerr << "  pq_sig: Winternitz signature in hex format (0x...)"
              << std::endl;
    std::cerr << "  to_address: Destination Ethereum address (0x...)"
              << std::endl;
    std::cerr << "  amount: Transfer amount in wei" << std::endl;
    std::cerr << "  wallet_owner_private_key: (optional) Private key for "
                 "wallet owner (0x...)"
              << std::endl;
    return false;
  }

  try {
    // Parse arguments
    WinternitzAddress winternitz_address =
        parseWinternitzAddressFromHex(args[0]);
    Signature pq_sig = parseSignatureFromHex(args[1]);
    Address to_address = parseAddress(args[2]);
    Amount amount = parseAmount(args[3]);

    // Get private key - prefer wallet owner private key if provided, otherwise
    // use environment variable
    PrivateKey private_key;
    if (args.size() == 7) {
      // Use provided wallet owner private key
      private_key = args[6];
    } else {
      // Use environment variable (deployer's private key)
      const char *env_private_key = std::getenv("PRIVATE_KEY");
      if (!env_private_key) {
        std::cerr << "Error: PRIVATE_KEY environment variable not set"
                  << std::endl;
        std::cerr
            << "Make sure to run this from e2e_test.sh or set PRIVATE_KEY "
               "in ethereum-sdk/.env"
            << std::endl;
        return false;
      }
      private_key = env_private_key;
    }

    // Get wallet address from factory using vaultId and classical public key
    Address wallet_address =
        factory_->getQuipWalletAddress(vaultId, classical_pubkey);

    if (wallet_address.empty() ||
        wallet_address == "0x0000000000000000000000000000000000000000") {
      std::cerr << "Error: No wallet found for vault ID " << toHex(vaultId)
                << " and classical public key " << classical_pubkey
                << std::endl;
      return false;
    }

    // Create wallet instance and perform transfer
    auto wallet = createWallet(wallet_address);
    bool success = wallet->transferWithWinternitz(
        winternitz_address, pq_sig, to_address, amount, private_key);

    if (success) {
      std::cout << "Transfer successful!" << std::endl;
      std::cout << "From: " << wallet_address << std::endl;
      std::cout << "To: " << to_address << std::endl;
      std::cout << "Amount: " << amount << " wei" << std::endl;
      return true;
    } else {
      std::cerr << "Error: Transfer failed" << std::endl;
      return false;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleExecute(const std::vector<std::string> &args) {
  if (args.size() != 6) {
    std::cerr
        << "Usage: execute <vault_id> <classical_pubkey> <winternitz_address> "
           "<pq_sig> <target_address> <opdata>"
        << std::endl;
    std::cerr << "  vault_id: 32-byte vault identifier in hex format (0x...)"
              << std::endl;
    std::cerr << "  classical_pubkey: Classical public key address (0x...)"
              << std::endl;
    std::cerr << "  winternitz_address: 64-byte Winternitz address in hex "
                 "format (0x...)"
              << std::endl;
    std::cerr << "  pq_sig: Winternitz signature in hex format (0x...)"
              << std::endl;
    std::cerr << "  target_address: Target contract address (0x...)"
              << std::endl;
    std::cerr << "  opdata: Operation data in hex format (0x...)" << std::endl;
    return false;
  }

  try {
    // Parse arguments
    VaultId vaultId = fromHex32(args[0]);
    Address classical_pubkey = parseAddress(args[1]);
    WinternitzAddress winternitz_address =
        parseWinternitzAddressFromHex(args[2]);
    Signature pq_sig = parseSignatureFromHex(args[3]);
    Address target_address = parseAddress(args[4]);
    std::vector<uint8_t> opdata = parseOpData(args[5]);

    // Get private key from environment variable
    const char *env_private_key = std::getenv("PRIVATE_KEY");
    if (!env_private_key) {
      std::cerr << "Error: PRIVATE_KEY environment variable not set"
                << std::endl;
      std::cerr << "Make sure to run this from e2e_test.sh or set PRIVATE_KEY "
                   "in ethereum-sdk/.env"
                << std::endl;
      return false;
    }
    PrivateKey private_key = env_private_key;

    // Get wallet address from factory using vaultId and classical public key
    Address wallet_address =
        factory_->getQuipWalletAddress(vaultId, classical_pubkey);

    if (wallet_address.empty() ||
        wallet_address == "0x0000000000000000000000000000000000000000") {
      std::cerr << "Error: No wallet found for vault ID " << toHex(vaultId)
                << " and classical public key " << classical_pubkey
                << std::endl;
      return false;
    }

    // Create wallet instance and perform execute
    auto wallet = createWallet(wallet_address);
    bool success = wallet->executeWithWinternitz(
        winternitz_address, pq_sig, target_address, opdata, private_key);

    if (success) {
      std::cout << "Execute successful!" << std::endl;
      std::cout << "Wallet: " << wallet_address << std::endl;
      std::cout << "Target: " << target_address << std::endl;
      std::cout << "Data: " << toHex(opdata) << std::endl;
      return true;
    } else {
      std::cerr << "Error: Execute failed" << std::endl;
      return false;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleChangeOwner(const std::vector<std::string> &args) {
  if (args.size() != 4) {
    std::cerr << "Usage: change-owner <vault_id> <classical_pubkey> "
                 "<winternitz_address> <pq_sig>"
              << std::endl;
    std::cerr << "  vault_id: 32-byte vault identifier in hex format (0x...)"
              << std::endl;
    std::cerr << "  classical_pubkey: Classical public key address (0x...)"
              << std::endl;
    std::cerr << "  winternitz_address: 64-byte Winternitz address in hex "
                 "format (0x...)"
              << std::endl;
    std::cerr << "  pq_sig: Winternitz signature in hex format (0x...)"
              << std::endl;
    return false;
  }

  try {
    // Parse arguments
    VaultId vaultId = fromHex32(args[0]);
    Address classical_pubkey = parseAddress(args[1]);
    WinternitzAddress winternitz_address =
        parseWinternitzAddressFromHex(args[2]);
    Signature pq_sig = parseSignatureFromHex(args[3]);

    // Get private key from environment variable
    const char *env_private_key = std::getenv("PRIVATE_KEY");
    if (!env_private_key) {
      std::cerr << "Error: PRIVATE_KEY environment variable not set"
                << std::endl;
      std::cerr << "Make sure to run this from e2e_test.sh or set PRIVATE_KEY "
                   "in ethereum-sdk/.env"
                << std::endl;
      return false;
    }
    PrivateKey private_key = env_private_key;

    // Get wallet address from factory using vaultId and classical public key
    Address wallet_address =
        factory_->getQuipWalletAddress(vaultId, classical_pubkey);

    if (wallet_address.empty() ||
        wallet_address == "0x0000000000000000000000000000000000000000") {
      std::cerr << "Error: No wallet found for vault ID " << toHex(vaultId)
                << " and classical public key " << classical_pubkey
                << std::endl;
      return false;
    }

    // Create wallet instance and perform change owner
    auto wallet = createWallet(wallet_address);
    bool success =
        wallet->changePqOwner(winternitz_address, pq_sig, private_key);

    if (success) {
      std::cout << "Change owner successful!" << std::endl;
      std::cout << "Wallet: " << wallet_address << std::endl;
      std::cout << "New PQ Owner Public Seed: "
                << toHex(winternitz_address.publicSeed) << std::endl;
      std::cout << "New PQ Owner Public Key Hash: "
                << toHex(winternitz_address.publicKeyHash) << std::endl;
      return true;
    } else {
      std::cerr << "Error: Change owner failed" << std::endl;
      return false;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleGetBalance(const std::vector<std::string> &args) {
  if (args.size() != 1) {
    std::cerr << "Usage: balance <address>" << std::endl;
    return false;
  }

  try {
    Address address = parseAddress(args[0]);
    auto wallet = createWallet(address);
    Amount balance = wallet->getBalance();
    std::cout << "Balance: " << balance << std::endl;
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleGetPqOwner(const std::vector<std::string> &args) {
  if (args.size() != 1) {
    std::cerr << "Usage: pq-owner <address>" << std::endl;
    return false;
  }

  try {
    Address address = parseAddress(args[0]);
    auto wallet = createWallet(address);
    Address owner = wallet->getPqOwner();
    std::cout << "PQ Owner: " << owner << std::endl;
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

void CLI::printUsage() const {
  std::cout << "Usage: quip-cli <command> [args]" << std::endl;
  std::cout << "Commands:" << std::endl;
  std::cout << "  deposit [--amount <amount>] [--entropy <entropy>]"
            << std::endl;
  std::cout
      << "    --amount: Amount in wei to deposit (default: 10000000000000000)"
      << std::endl;
  std::cout << "    --entropy: Optional hex string for deterministic vault ID"
            << std::endl;
  std::cout << "  transfer <vault_id> <classical_pubkey> <winternitz_address> "
               "<pq_sig> <to_address> <amount> [wallet_owner_private_key]"
            << std::endl;
  std::cout << "  execute <vault_id> <classical_pubkey> <winternitz_address> "
               "<pq_sig> <target_address> <opdata>"
            << std::endl;
  std::cout
      << "  change-owner <vault_id> <classical_pubkey> <winternitz_address> "
         "<pq_sig>"
      << std::endl;
  std::cout << "  balance <address>" << std::endl;
  std::cout << "  pq-owner <address>" << std::endl;
}

std::string CLI::getContractAddress(const std::string &contract_name) const {
  if (!contract_address_.empty()) {
    return contract_address_;
  }
  // If no contract address provided, this indicates an error in the current
  // setup
  throw std::runtime_error(
      "No contract address provided. Use --contract-address option.");
}

std::array<uint8_t, 32> CLI::parseVaultId(const std::string &vault_id) const {
  // Parse a 32-byte vault ID from hex
  return fromHex32(vault_id);
}

Address CLI::parseAddress(const std::string &address) const {
  // Validate Ethereum address: must be 42 chars, start with 0x, and be hex
  if (address.size() != 42 || address.substr(0, 2) != "0x") {
    throw std::runtime_error(
        "Invalid address format: must be 0x followed by 40 hex characters");
  }
  for (size_t i = 2; i < 42; ++i) {
    char c = address[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      throw std::runtime_error(
          "Invalid address format: contains non-hex character");
    }
  }
  return address;
}

Amount CLI::parseAmount(const std::string &amount) const {
  try {
    return std::stoull(amount);
  } catch (const std::exception &) {
    throw std::runtime_error("Invalid amount format");
  }
}

std::vector<uint8_t> CLI::parseOpData(const std::string &opdata) const {
  // Parse operation data from hex
  return fromHex(opdata);
}

std::vector<uint8_t> CLI::parsePublicKey(const std::string &pubkey) const {
  // Parse a 32-byte public key from hex
  return fromHex(pubkey);
}

std::vector<uint8_t> CLI::parseSignature(const std::string &sig) const {
  // Parse a signature as a vector of 32-byte arrays from hex
  std::vector<uint8_t> bytes = fromHex(sig);
  if (bytes.size() % 32 != 0) {
    throw std::runtime_error("Invalid signature length");
  }
  return bytes;
}

std::vector<uint8_t> CLI::parsePrivateKey(const std::string &key) const {
  // Parse a 32-byte private key from hex
  return fromHex(key);
}

} // namespace quip