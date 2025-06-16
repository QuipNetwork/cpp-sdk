#pragma once

#include <array>
#include <curl/curl.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>
#include <wotsplus.hpp>

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

// Common functions
inline string toHex(const vector<uint8_t> &data) {
  string result;
  result.reserve(data.size() * 2);
  for (uint8_t byte : data) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", byte);
    result += hex;
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

} // namespace quip