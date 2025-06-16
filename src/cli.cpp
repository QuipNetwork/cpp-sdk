#include "cli.hpp"
#include "common.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace quip {

// Helper: parse a hex string into a PublicKey (array<uint8_t, 32>)
static PublicKey parsePublicKeyFromHex(const std::string &hex) {
  std::vector<uint8_t> bytes = fromHex(hex);
  if (bytes.size() != 32)
    throw std::runtime_error("Invalid pubkey length");
  PublicKey arr;
  std::copy(bytes.begin(), bytes.end(), arr.begin());
  return arr;
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

CLI::CLI(const std::string &rpc_url) : rpc_url_(rpc_url) {
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
  if (args.size() != 3) {
    std::cerr << "Usage: deposit <pq_pubkey> <pq_sig> <private_key>"
              << std::endl;
    return false;
  }

  try {
    PublicKey pq_pubkey = parsePublicKeyFromHex(args[0]);
    Signature pq_sig = parseSignatureFromHex(args[1]);
    PrivateKey private_key = args[2];

    return factory_->depositToWinternitz(pq_pubkey, pq_sig, private_key);
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleTransfer(const std::vector<std::string> &args) {
  if (args.size() != 5) {
    std::cerr << "Usage: transfer <pq_pubkey> <pq_sig> <to_address> <amount> "
                 "<private_key>"
              << std::endl;
    return false;
  }

  try {
    PublicKey pq_pubkey = parsePublicKeyFromHex(args[0]);
    Signature pq_sig = parseSignatureFromHex(args[1]);
    Address to_address = parseAddress(args[2]);
    Amount amount = parseAmount(args[3]);
    PrivateKey private_key = args[4];

    Address wallet_address = factory_->getQuipWalletAddress(pq_pubkey);
    auto wallet = createWallet(wallet_address);
    return wallet->transferWithWinternitz(pq_pubkey, pq_sig, to_address, amount,
                                          private_key);
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleExecute(const std::vector<std::string> &args) {
  if (args.size() != 5) {
    std::cerr << "Usage: execute <pq_pubkey> <pq_sig> <target_address> "
                 "<opdata> <private_key>"
              << std::endl;
    return false;
  }

  try {
    PublicKey pq_pubkey = parsePublicKeyFromHex(args[0]);
    Signature pq_sig = parseSignatureFromHex(args[1]);
    Address target_address = parseAddress(args[2]);
    std::vector<uint8_t> opdata = parseOpData(args[3]);
    PrivateKey private_key = args[4];

    Address wallet_address = factory_->getQuipWalletAddress(pq_pubkey);
    auto wallet = createWallet(wallet_address);
    return wallet->executeWithWinternitz(pq_pubkey, pq_sig, target_address,
                                         opdata, private_key);
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
  }
}

bool CLI::handleChangeOwner(const std::vector<std::string> &args) {
  if (args.size() != 3) {
    std::cerr << "Usage: change-owner <pq_pubkey> <pq_sig> <private_key>"
              << std::endl;
    return false;
  }

  try {
    PublicKey pq_pubkey = parsePublicKeyFromHex(args[0]);
    Signature pq_sig = parseSignatureFromHex(args[1]);
    PrivateKey private_key = args[2];

    Address wallet_address = factory_->getQuipWalletAddress(pq_pubkey);
    auto wallet = createWallet(wallet_address);
    return wallet->changePqOwner(pq_pubkey, pq_sig, private_key);
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
  std::cout << "  deposit <pq_pubkey> <pq_sig> <private_key>" << std::endl;
  std::cout
      << "  transfer <pq_pubkey> <pq_sig> <to_address> <amount> <private_key>"
      << std::endl;
  std::cout << "  execute <pq_pubkey> <pq_sig> <target_address> <opdata> "
               "<private_key>"
            << std::endl;
  std::cout << "  change-owner <pq_pubkey> <pq_sig> <private_key>" << std::endl;
  std::cout << "  balance <address>" << std::endl;
  std::cout << "  pq-owner <address>" << std::endl;
}

std::string CLI::getContractAddress(const std::string &contract_name) const {
  // TODO: Implement contract address lookup
  return "0x0000000000000000000000000000000000000000";
}

std::array<uint8_t, 32> CLI::parseVaultId(const std::string &vault_id) const {
  // TODO: Implement vault ID parsing
  return std::array<uint8_t, 32>{};
}

Address CLI::parseAddress(const std::string &address) const {
  // TODO: Implement address parsing
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
  // TODO: Implement operation data parsing
  return fromHex(opdata);
}

std::vector<uint8_t> CLI::parsePublicKey(const std::string &pubkey) const {
  // TODO: Implement public key parsing
  return std::vector<uint8_t>{};
}

std::vector<uint8_t> CLI::parseSignature(const std::string &sig) const {
  // TODO: Implement signature parsing
  return std::vector<uint8_t>{};
}

std::vector<uint8_t> CLI::parsePrivateKey(const std::string &key) const {
  // TODO: Implement private key parsing
  return std::vector<uint8_t>{};
}

} // namespace quip