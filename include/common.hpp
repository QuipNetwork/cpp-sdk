#pragma once

#include <array>
#include <curl/curl.h>
#include <memory>
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

inline vector<uint8_t> fromHex(const string &hex) {
  if (hex.substr(0, 2) == "0x") {
    return fromHex(hex.substr(2));
  }
  vector<uint8_t> result;
  result.reserve(hex.length() / 2);
  for (size_t i = 0; i < hex.length(); i += 2) {
    string byteString = hex.substr(i, 2);
    uint8_t byte =
        static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
    result.push_back(byte);
  }
  return result;
}

inline array<uint8_t, 32> fromHex32(const string &hex) {
  vector<uint8_t> bytes = fromHex(hex);
  if (bytes.size() != 32) {
    throw runtime_error(
        "Hex string must be exactly 32 bytes (64 hex characters)");
  }
  array<uint8_t, 32> result;
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

// Generate a random vault ID using entropy
inline VaultId generateVaultId(const string &entropy = "") {
  VaultId vaultId;
  if (entropy.empty()) {
    // Generate random vault ID
    for (int i = 0; i < 32; ++i) {
      vaultId[i] = static_cast<uint8_t>(rand() % 256);
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

} // namespace quip