#pragma once

#include "keccak.h"
#include <array>
#include <curl/curl.h>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace quip {

using std::array;
using std::runtime_error;
using std::string;
using std::unique_ptr;
using std::vector;

// Common types
using Address = string;
using PrivateKey = string;
using PublicKey = array<uint8_t, 32>;
using Signature = vector<array<uint8_t, 32>>;
using Amount = uint64_t;
using VaultId = array<uint8_t, 32>; // bytes32 for vault identifier

// WinternitzAddress structure matching the Solidity contract
struct WinternitzAddress {
  array<uint8_t, 32> publicSeed;    // bytes32 publicSeed
  array<uint8_t, 32> publicKeyHash; // bytes32 publicKeyHash
};

// Common functions
inline string toHex(const vector<uint8_t> &data) {
  string result;
  result.reserve(data.size() * 2);
  for (uint8_t byte : data) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", byte);
    result += hex;
  }
  // Only add '0x' if not already present
  if (result.rfind("0x", 0) == 0) {
    return result;
  }
  return "0x" + result;
}

inline string toHex(const array<uint8_t, 32> &data) {
  string result;
  result.reserve(64);
  for (uint8_t byte : data) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", byte);
    result += hex;
  }
  // Only add '0x' if not already present
  if (result.rfind("0x", 0) == 0) {
    return result;
  }
  return "0x" + result;
}

inline vector<uint8_t> fromHex(const string &hex, size_t expected_length = 0) {
  string hex_str = hex;
  if (hex.substr(0, 2) == "0x") {
    hex_str = hex.substr(2);
  }

  if (expected_length > 0 && hex_str.length() != expected_length * 2) {
    throw runtime_error("Invalid hex string length: expected " +
                        std::to_string(expected_length) + " bytes, got " +
                        std::to_string(hex_str.length() / 2) + " bytes");
  }

  vector<uint8_t> result;
  result.reserve(hex_str.length() / 2);
  for (size_t i = 0; i < hex_str.length(); i += 2) {
    string byteString = hex_str.substr(i, 2);
    uint8_t byte =
        static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
    result.push_back(byte);
  }
  return result;
}

inline array<uint8_t, 32> fromHex32(const string &hex) {
  vector<uint8_t> bytes = fromHex(hex, 32);
  array<uint8_t, 32> result;
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

// Generate a random vault ID using entropy
inline VaultId generateVaultId(const string &entropy = "") {
  VaultId vaultId;
  if (entropy.empty()) {
    // Generate cryptographically secure random vault ID
    std::random_device rd;
    for (size_t i = 0; i < 32; i += 4) {
      uint32_t random_val = rd();
      vaultId[i] = static_cast<uint8_t>(random_val & 0xFF);
      if (i + 1 < 32)
        vaultId[i + 1] = static_cast<uint8_t>((random_val >> 8) & 0xFF);
      if (i + 2 < 32)
        vaultId[i + 2] = static_cast<uint8_t>((random_val >> 16) & 0xFF);
      if (i + 3 < 32)
        vaultId[i + 3] = static_cast<uint8_t>((random_val >> 24) & 0xFF);
    }
  } else {
    // Use provided entropy to generate deterministic vault ID
    vector<uint8_t> entropyBytes = fromHex(entropy);
    if (entropyBytes.size() < 32) {
      // Pad with zeros if entropy is too short
      entropyBytes.resize(32, 0);
    } else if (entropyBytes.size() > 32) {
      // Truncate if entropy is too long
      entropyBytes.resize(32);
    }
    std::copy(entropyBytes.begin(), entropyBytes.end(), vaultId.begin());
  }
  return vaultId;
}

// ABI encoding function (shared between quip_wallet and quip_factory)
string abiEncode(const string &function_name, const string &abi_json,
                 const string &params_json);

// Get chain ID from RPC endpoint
uint64_t getChainId(const string &rpc_url);

inline string toHex(const Signature &sig) {
  // Flatten the signature (vector<array<uint8_t, 32>>) into a single
  // vector<uint8_t>
  std::vector<uint8_t> flat;
  for (const auto &chunk : sig) {
    flat.insert(flat.end(), chunk.begin(), chunk.end());
  }
  return toHex(flat);
}

// Converts a lowercase hex Ethereum address to EIP-55 checksum address
inline std::string toChecksumAddress(const std::string &address) {
  // Remove 0x prefix if present and convert to lowercase
  std::string stripAddress = address;
  if (stripAddress.rfind("0x", 0) == 0 || stripAddress.rfind("0X", 0) == 0) {
    stripAddress = stripAddress.substr(2);
  }
  std::transform(stripAddress.begin(), stripAddress.end(), stripAddress.begin(),
                 ::tolower);

  // Validate address: must be 40 hex chars and all hex digits
  if (stripAddress.size() != 40 ||
      !std::all_of(stripAddress.begin(), stripAddress.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
      })) {
    throw std::invalid_argument("Invalid Ethereum address: " + address);
  }

  // Keccak-256 hash of the address (no 0x prefix)
  std::vector<uint8_t> addr_bytes(stripAddress.begin(), stripAddress.end());
  Keccak keccak(Keccak::Keccak256);
  std::string hash_hex = keccak(addr_bytes.data(), addr_bytes.size());

  // Build the checksum address
  std::string checksumAddress = "0x";
  for (size_t i = 0; i < stripAddress.size(); ++i) {
    int hash_nibble = std::stoi(hash_hex.substr(i, 1), nullptr, 16);
    if (hash_nibble >= 8) {
      checksumAddress += std::toupper(stripAddress[i]);
    } else {
      checksumAddress += stripAddress[i];
    }
  }
  return checksumAddress;
}

} // namespace quip