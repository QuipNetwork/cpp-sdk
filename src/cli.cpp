#include "../include/cli.hpp"
#include "../include/common.hpp"
#include "keccak.h"
#include "wotsplus.hpp"
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <optional>
#include <random>
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
  std::vector<uint8_t> bytes = fromHex(hex, 64);

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
  std::string command = "cd " +
                        std::string(getenv("PWD") ? getenv("PWD") : ".") +
                        "/ethereum-sdk && node -e \"console.log(new "
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

// Helper: generate a random 32-byte array
static std::array<uint8_t, 32> randomSeed32() {
  std::array<uint8_t, 32> seed;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint16_t> dis(0, 255);
  for (size_t i = 0; i < 32; ++i) {
    seed[i] = static_cast<uint8_t>(dis(gen));
  }
  return seed;
}

// QuipSigner: Deterministic Winternitz keypair generator using quantum secret
// and vaultId
class QuipSigner {
public:
  QuipSigner(const std::array<uint8_t, 32> &quantum_secret_raw)
      : wots_(keccak256) {
    quantum_secret_ = quantum_secret_raw;
  }

  // Deterministically generate keypair for a given vaultId
  std::pair<WinternitzAddress, array<uint8_t, 32>>
  generateKeyPair(const std::array<uint8_t, 32> &vaultId) {
    // Use a random 32-byte public seed for the next PQ owner (like TS SDK)
    std::array<uint8_t, 32> public_seed = randomSeed32();
    return recoverKeyPair(vaultId, public_seed);
  }

  // Deterministically recover keypair for a given vaultId and publicSeed
  std::pair<WinternitzAddress, array<uint8_t, 32>>
  recoverKeyPair(const std::array<uint8_t, 32> &vaultId,
                 const std::array<uint8_t, 32> &publicSeed) {
    // Create the private seed by concatenating the quantum secret and
    // the vaultId. This is not hashed again here, but is passed to
    // generate_key_pair, which will hash it with the public seed.
    std::vector<uint8_t> private_seed(quantum_secret_.begin(),
                                      quantum_secret_.end());
    private_seed.insert(private_seed.end(), vaultId.begin(), vaultId.end());

    // Generate keypair using the two-parameter interface (protocol-compatible)
    auto [public_key, private_key] =
        wots_.generate_key_pair(private_seed, publicSeed);

    // Create WinternitzAddress from the generated public key
    WinternitzAddress pqAddress;
    std::copy(public_key.begin(), public_key.begin() + 32,
              pqAddress.publicSeed.begin());
    std::copy(public_key.begin() + 32, public_key.end(),
              pqAddress.publicKeyHash.begin());
    return {pqAddress, private_key};
  }

  // Sign a message using a recovered keypair
  Signature sign(const std::array<uint8_t, 32> &message,
                 const array<uint8_t, 32> &private_key,
                 const std::array<uint8_t, 32> &publicSeed) {
    // Sign the message with the provided private key and public seed
    return wots_.sign(private_key, publicSeed, message);
  }

private:
  std::array<uint8_t, 32> quantum_secret_;
  hashsigs::WOTSPlus wots_;
};

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

  if (command == "generate-keypair") {
    return handleGenerateKeypair(command_args);
  } else if (command == "recover-keypair") {
    return handleRecoverKeypair(command_args);
  } else if (command == "sign") {
    return handleSign(command_args);
  } else if (command == "pq-owner") {
    return handleGetPqOwner(command_args);
  } else if (command == "change-pq-owner") {
    return handleChangePqOwner(command_args);
  } else if (command == "balance") {
    return handleGetBalance(command_args);
  } else if (command == "transfer") {
    return handleTransfer(command_args);
  } else if (command == "execute") {
    return handleExecute(command_args);
  } else if (command == "deposit") {
    return handleDeposit(command_args);
  } else {
    std::cerr << "Unknown command: " << command << std::endl;
    printUsage();
    return false;
  }
}

bool CLI::handleDeposit(const std::vector<std::string> &args) {
  Amount amount = 0;
  std::string entropy = "";
  std::string vault_id_hex = "";

  // Parse flags
  for (size_t i = 0; i < args.size(); ++i) {
    if (args[i] == "--amount" && i + 1 < args.size()) {
      std::string amount_str = args[++i];
      // Remove quotes if present
      if (amount_str.front() == '"' && amount_str.back() == '"') {
        amount_str = amount_str.substr(1, amount_str.size() - 2);
      }
      amount = std::stoull(amount_str);
    } else if (args[i] == "--entropy" && i + 1 < args.size()) {
      entropy = args[++i];
      if (entropy.front() == '"' && entropy.back() == '"') {
        entropy = entropy.substr(1, entropy.size() - 2);
      }
    } else if (args[i] == "--vault-id" && i + 1 < args.size()) {
      vault_id_hex = args[++i];
      if (vault_id_hex.front() == '"' && vault_id_hex.back() == '"') {
        vault_id_hex = vault_id_hex.substr(1, vault_id_hex.size() - 2);
      }
    } else {
      std::cerr << "Unknown or incomplete flag: " << args[i] << std::endl;
      std::cerr << "Usage: deposit [--amount <amount>] [--entropy <entropy>] "
                   "[--vault-id <vault_id>]"
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

    // Prepare quantum secret
    std::array<uint8_t, 32> quantum_secret;
    bool secret_was_generated = false;
    if (entropy.empty()) {
      secret_was_generated = true;
      for (int i = 0; i < 32; ++i) {
        quantum_secret[i] = static_cast<uint8_t>(rand() % 256);
      }
    } else {
      std::vector<uint8_t> entropyBytes = fromHex(entropy);
      if (entropyBytes.size() != 32) {
        throw std::runtime_error(
            "Provided entropy for quantum secret must be a 32-byte hex string");
      }
      std::copy(entropyBytes.begin(), entropyBytes.end(),
                quantum_secret.begin());
    }

    // Generate or use provided vault ID
    VaultId vaultId;
    if (vault_id_hex.empty()) {
      vaultId = generateVaultId("");
    } else {
      vaultId = generateVaultId(vault_id_hex);
    }

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

    // Generate Winternitz keypair using QuipSigner
    QuipSigner signer(quantum_secret);
    auto [winternitz_address, winternitz_private_key] =
        signer.generateKeyPair(vaultId);

    // Call the factory to create the wallet
    Address wallet_address = factory_->depositToWinternitz(
        vaultId, classical_pubkey, winternitz_address, private_key, amount);

    if (!wallet_address.empty() &&
        wallet_address != "0x0000000000000000000000000000000000000000") {
      if (secret_was_generated) {
        std::cout << "Generated Quantum Secret: " << toHex(quantum_secret)
                  << std::endl;
      }
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
  if (args.size() != 4) {
    std::cerr << "Usage: transfer <quantum_secret> <quip_wallet_address> "
                 "<to_address> "
                 "<amount>"
              << std::endl;
    std::cerr << "  quantum_secret: 32-byte hex string (0x...)" << std::endl;
    std::cerr << "  quip_wallet_address: Address of the Quip wallet (0x...)"
              << std::endl;
    std::cerr << "  to_address: Destination Ethereum address (0x...)"
              << std::endl;
    std::cerr << "  amount: Transfer amount in wei" << std::endl;
    return false;
  }

  try {
    // Parse arguments
    std::string quantum_secret_hex = args[0];
    if (quantum_secret_hex.front() == '"' && quantum_secret_hex.back() == '"') {
      quantum_secret_hex =
          quantum_secret_hex.substr(1, quantum_secret_hex.size() - 2);
    }
    std::vector<uint8_t> quantum_secret_vec = fromHex(quantum_secret_hex);

    std::string quip_wallet_address_str = args[1];
    if (quip_wallet_address_str.front() == '"' &&
        quip_wallet_address_str.back() == '"') {
      quip_wallet_address_str =
          quip_wallet_address_str.substr(1, quip_wallet_address_str.size() - 2);
    }
    Address quip_wallet_address = parseAddress(quip_wallet_address_str);

    std::string to_address_str = args[2];
    if (to_address_str.front() == '"' && to_address_str.back() == '"') {
      to_address_str = to_address_str.substr(1, to_address_str.size() - 2);
    }
    Address to_address = parseAddress(to_address_str);

    std::string amount_str = args[3];
    if (amount_str.front() == '"' && amount_str.back() == '"') {
      amount_str = amount_str.substr(1, amount_str.size() - 2);
    }
    Amount amount = parseAmount(amount_str);

    if (quantum_secret_vec.size() != 32) {
      throw std::runtime_error("quantum_secret must be 32 bytes");
    }
    std::array<uint8_t, 32> quantum_secret;
    std::copy(quantum_secret_vec.begin(), quantum_secret_vec.end(),
              quantum_secret.begin());

    // Get private key from environment
    const char *env_private_key = std::getenv("PRIVATE_KEY");
    if (!env_private_key) {
      std::cerr << "Error: PRIVATE_KEY environment variable not set"
                << std::endl;
      return false;
    }
    PrivateKey private_key = env_private_key;

    // Derive classical public key from private key
    Address classical_pubkey = deriveClassicalPublicKey(private_key);

    // Create wallet instance to get current PQ owner
    auto wallet = createWallet(quip_wallet_address);
    std::string current_pq_owner_hex = wallet->getPqOwner();

    if (current_pq_owner_hex.empty() ||
        current_pq_owner_hex == "0x0000000000000000000000000000000000000000") {
      std::cerr << "Error: Could not get PQ owner from wallet" << std::endl;
      return false;
    }

    WinternitzAddress current_winternitz_address =
        parseWinternitzAddressFromHex(current_pq_owner_hex);
    auto public_seed = current_winternitz_address.publicSeed;

    // We need to find the vault ID for this wallet
    // For now, we'll iterate through vaults to find the matching one
    // TODO: Add a more efficient method to get vault ID from wallet address
    auto vaults = factory_->getVaults(classical_pubkey);
    VaultId vault_id;
    bool found_vault = false;

    for (const auto &vault : vaults) {
      if (vault.classical_address == quip_wallet_address) {
        vault_id = vault.id;
        found_vault = true;
        break;
      }
    }

    if (!found_vault) {
      std::cerr << "Error: Could not find vault ID for wallet address "
                << quip_wallet_address << std::endl;
      return false;
    }

    // Create QuipSigner and generate keys
    QuipSigner signer(quantum_secret);

    // Recover the current keypair using the public seed
    auto [recovered_winternitz_address, current_private_key] =
        signer.recoverKeyPair(vault_id, public_seed);

    // Check that the recovered public key hash matches the one from the chain
    if (recovered_winternitz_address.publicKeyHash !=
        current_winternitz_address.publicKeyHash) {
      std::cerr << "Error: Recovered public key hash does not match on-chain "
                   "public key hash"
                << std::endl;
      return false;
    }

    // Generate the next keypair for the transfer
    auto [next_winternitz_address, next_private_key] =
        signer.generateKeyPair(vault_id);

    // Create the transfer message data using ethers.js solidityPacked
    // Format: current_pubkey + next_pubkey + recipient + amount
    std::string command =
        "cd " + std::string(getenv("PWD") ? getenv("PWD") : ".") +
        "/ethereum-sdk && node -e "
        "\"console.log(require('ethers').solidityPacked(['bytes32', 'bytes32', "
        "'bytes32', 'bytes32', 'address', 'uint256'], ['" +
        toHex(current_winternitz_address.publicSeed) + "', '" +
        toHex(current_winternitz_address.publicKeyHash) + "', '" +
        toHex(next_winternitz_address.publicSeed) + "', '" +
        toHex(next_winternitz_address.publicKeyHash) + "', '" + to_address +
        "', '" + std::to_string(amount) + "']))\"";

    std::cerr << "Debug: solidityPacked command: " << command << std::endl;

    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
      throw std::runtime_error(
          "Failed to execute ethers.js solidityPacked command");
    }

    std::string packed_data;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
      packed_data += buffer;
    }

    int status = pclose(pipe);
    if (status != 0) {
      throw std::runtime_error("ethers.js solidityPacked command failed");
    }

    // Remove newline and convert to bytes
    if (!packed_data.empty() && packed_data[packed_data.length() - 1] == '\n') {
      packed_data.erase(packed_data.length() - 1);
    }

    std::cerr << "Debug: packed_data: " << packed_data << std::endl;

    std::vector<uint8_t> message_data =
        fromHex(packed_data.substr(2)); // Remove 0x prefix

    // Hash the packed data to get the message hash
    std::array<uint8_t, 32> message_hash = keccak256(message_data);

    std::cerr << "Debug: message_hash: " << toHex(message_hash) << std::endl;

    // Sign the message with the current private key
    Signature pq_sig =
        signer.sign(message_hash, current_private_key, public_seed);

    std::cerr << "Debug: signature size: " << pq_sig.size() << std::endl;
    for (size_t i = 0; i < pq_sig.size(); ++i) {
      std::cerr << "Debug: signature[" << i << "]: " << toHex(pq_sig[i])
                << std::endl;
    }

    // Perform the transfer
    bool success = wallet->transferWithWinternitz(next_winternitz_address,
                                                  pq_sig, to_address, amount);

    if (success) {
      std::cout << "Transfer successful!" << std::endl;
      std::cout << "From: " << quip_wallet_address << std::endl;
      std::cout << "To: " << to_address << std::endl;
      std::cout << "Amount: " << amount << " wei" << std::endl;
      std::cout << "Vault ID: " << toHex(vault_id) << std::endl;
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
    // const char *env_private_key = std::getenv("PRIVATE_KEY"); // No longer
    // needed here
    // ...
    // PrivateKey private_key = env_private_key;

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
    bool success = wallet->executeWithWinternitz(winternitz_address, pq_sig,
                                                 target_address, opdata);

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

bool CLI::handleChangePqOwner(const std::vector<std::string> &args) {
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
    // const char *env_private_key = std::getenv("PRIVATE_KEY"); // No longer
    // needed here
    // ...
    // PrivateKey private_key = env_private_key;

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
    bool success = wallet->changePqOwner(winternitz_address, pq_sig);

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

bool CLI::handleGenerateKeypair(const std::vector<std::string> &args) {
  if (args.size() != 2) {
    std::cerr << "Usage: generate-keypair <quantum_secret> <vault_id>"
              << std::endl;
    std::cerr << "  quantum_secret: 32-byte hex string (0x...)" << std::endl;
    std::cerr << "  vault_id: 32-byte hex string (0x...)" << std::endl;
    return false;
  }
  try {
    std::vector<uint8_t> quantum_secret_vec = fromHex(args[0]);
    std::vector<uint8_t> vault_id_vec = fromHex(args[1]);
    if (quantum_secret_vec.size() != 32 || vault_id_vec.size() != 32) {
      throw std::runtime_error("quantum_secret and vault_id must be 32 bytes");
    }
    std::array<uint8_t, 32> quantum_secret;
    std::copy(quantum_secret_vec.begin(), quantum_secret_vec.end(),
              quantum_secret.begin());
    std::array<uint8_t, 32> vault_id;
    std::copy(vault_id_vec.begin(), vault_id_vec.end(), vault_id.begin());
    QuipSigner signer(quantum_secret);
    auto [pqAddress, private_key] = signer.generateKeyPair(vault_id);
    std::cout << "Winternitz Public Seed: " << toHex(pqAddress.publicSeed)
              << std::endl;
    std::cout << "Winternitz Public Key Hash: "
              << toHex(pqAddress.publicKeyHash) << std::endl;
    std::cout << "Winternitz Private Key: " << toHex(private_key) << std::endl;
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleRecoverKeypair(const std::vector<std::string> &args) {
  if (args.size() != 3) {
    std::cerr << "Usage: recover-keypair <quantum_secret_hex> <vault_id_hex> "
                 "<public_seed_hex>"
              << std::endl;
    return false;
  }

  try {
    std::string quantum_secret_hex = args[0];
    if (quantum_secret_hex.front() == '"' && quantum_secret_hex.back() == '"') {
      quantum_secret_hex =
          quantum_secret_hex.substr(1, quantum_secret_hex.size() - 2);
    }
    std::array<uint8_t, 32> quantum_secret = fromHex32(quantum_secret_hex);

    std::string vault_id_hex = args[1];
    if (vault_id_hex.front() == '"' && vault_id_hex.back() == '"') {
      vault_id_hex = vault_id_hex.substr(1, vault_id_hex.size() - 2);
    }
    std::array<uint8_t, 32> vault_id = fromHex32(vault_id_hex);

    std::string public_seed_hex = args[2];
    if (public_seed_hex.front() == '"' && public_seed_hex.back() == '"') {
      public_seed_hex = public_seed_hex.substr(1, public_seed_hex.size() - 2);
    }
    std::array<uint8_t, 32> public_seed = fromHex32(public_seed_hex);

    QuipSigner signer(quantum_secret);
    auto [pq_address, pq_private_key] =
        signer.recoverKeyPair(vault_id, public_seed);

    std::cout << "Winternitz Public Seed: " << toHex(pq_address.publicSeed)
              << std::endl;
    std::cout << "Winternitz Public Key Hash: "
              << toHex(pq_address.publicKeyHash) << std::endl;
    std::cout << "Winternitz Private Key: " << toHex(pq_private_key)
              << std::endl;

    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleSign(const std::vector<std::string> &args) {
  if (args.size() != 3) {
    std::cerr
        << "Usage: sign <quantum_secret> <vault_id> <public_seed> <message>"
        << std::endl;
    std::cerr << "  quantum_secret: 32-byte hex string (0x...)" << std::endl;
    std::cerr << "  vault_id: 32-byte hex string (0x...)" << std::endl;
    std::cerr << "  public_seed: 32-byte hex string (0x...)" << std::endl;
    std::cerr << "  message: 32-byte hex string (0x...)" << std::endl;
    return false;
  }
  try {
    std::vector<uint8_t> quantum_secret_vec = fromHex(args[0]);
    std::vector<uint8_t> vault_id_vec = fromHex(args[1]);
    std::vector<uint8_t> public_seed_vec = fromHex(args[2]);
    std::vector<uint8_t> message_vec = fromHex(args[3]);
    if (quantum_secret_vec.size() != 32 || vault_id_vec.size() != 32 ||
        public_seed_vec.size() != 32 || message_vec.size() != 32) {
      throw std::runtime_error("All arguments must be 32 bytes");
    }
    std::array<uint8_t, 32> quantum_secret;
    std::copy(quantum_secret_vec.begin(), quantum_secret_vec.end(),
              quantum_secret.begin());
    std::array<uint8_t, 32> vault_id;
    std::copy(vault_id_vec.begin(), vault_id_vec.end(), vault_id.begin());
    std::array<uint8_t, 32> public_seed;
    std::copy(public_seed_vec.begin(), public_seed_vec.end(),
              public_seed.begin());
    std::array<uint8_t, 32> message;
    std::copy(message_vec.begin(), message_vec.end(), message.begin());
    QuipSigner signer(quantum_secret);
    auto [pqAddress, private_key] =
        signer.recoverKeyPair(vault_id, public_seed);
    auto signature = signer.sign(message, private_key, public_seed);
    // Print as a single hex string
    std::vector<uint8_t> sig_bytes;
    for (const auto &seg : signature) {
      sig_bytes.insert(sig_bytes.end(), seg.begin(), seg.end());
    }
    std::cout << "Signature: " << toHex(sig_bytes) << std::endl;
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

void CLI::printUsage() const {
  std::cout << "Usage: quip-cli <command> [options]" << std::endl;
  std::cout << "Commands:" << std::endl;
  std::cout << "  deposit [--amount <amount>] [--entropy <entropy>] "
               "[--vault-id <vault_id>]"
            << std::endl;
  std::cout
      << "    --amount: Amount in wei to deposit (default: 10000000000000000)"
      << std::endl;
  std::cout << "    --entropy: Optional hex string for deterministic vault ID"
            << std::endl;
  std::cout
      << "    --vault-id: Optional hex string for specific vault ID (32 bytes)"
      << std::endl;
  std::cout << "  transfer <quantum_secret> <quip_wallet_address> <to_address> "
               "<amount>"
            << std::endl;
  std::cout << "  execute <vault_id> <classical_pubkey> <winternitz_address> "
               "<pq_sig> <target_address> <opdata>"
            << std::endl;
  std::cout << "  balance <address>" << std::endl;
  std::cout << "  pq-owner <address>" << std::endl;
  std::cout << "  change-owner <vault_id> <classical_pubkey> "
               "<winternitz_address> <pq_sig>"
            << std::endl;
  std::cout << "  generate-keypair <quantum_secret> <vault_id>" << std::endl;
  std::cout << "  recover-keypair <quantum_secret_hex> <vault_id_hex> "
               "<public_seed_hex>"
            << std::endl;
  std::cout << "  sign <quantum_secret> <vault_id> <public_seed> <message>"
            << std::endl;
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