#include "../include/common.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace quip {

// Shared ABI encoding function implementation
std::string abiEncode(const std::string &function_name,
                      const std::string &abi_json,
                      const std::string &params_json) {
  // Escape quotes in the JSON strings for shell command
  std::string escaped_abi = abi_json;
  std::string escaped_params = params_json;

  // Replace " with \" for shell safety
  size_t pos = 0;
  while ((pos = escaped_abi.find("\"", pos)) != std::string::npos) {
    escaped_abi.replace(pos, 1, "\\\"");
    pos += 2;
  }
  pos = 0;
  while ((pos = escaped_params.find("\"", pos)) != std::string::npos) {
    escaped_params.replace(pos, 1, "\\\"");
    pos += 2;
  }

  std::string command =
      "npx ts-node " + std::string(getenv("PWD") ? getenv("PWD") : ".") +
      "/ethereum-sdk/scripts/abiEncode.ts \"" + escaped_abi + "\" \"" +
      function_name + "\" \"" + escaped_params + "\"";

  FILE *pipe = popen(command.c_str(), "r");
  if (!pipe) {
    throw std::runtime_error("Failed to execute ABI encoding script");
  }

  std::string result;
  char buffer[128];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }

  int status = pclose(pipe);
  if (status != 0) {
    throw std::runtime_error("ABI encoding script failed with status " +
                             std::to_string(status));
  }

  // Remove trailing newline
  if (!result.empty() && result.back() == '\n') {
    result.pop_back();
  }

  return result;
}

// Helper function for curl write callback
static size_t WriteCallback(void *contents, size_t size, size_t nmemb,
                           std::string *userp) {
  userp->append((char *)contents, size * nmemb);
  return size * nmemb;
}

// Get chain ID from RPC endpoint
uint64_t getChainId(const std::string &rpc_url) {
  CURL *curl = curl_easy_init();
  if (!curl) {
    throw std::runtime_error("Failed to initialize CURL");
  }

  // Create JSON-RPC request for eth_chainId
  std::string request = R"({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})";
  std::string response_string;

  curl_easy_setopt(curl, CURLOPT_URL, rpc_url.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
  
  // Add headers
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  if (res != CURLE_OK) {
    std::cerr << "Warning: Failed to get chain ID from RPC: " 
              << curl_easy_strerror(res) << std::endl;
    return 31337; // Default to Hardhat
  }

  try {
    // Parse JSON response
    size_t json_start = response_string.find('{');
    if (json_start == std::string::npos) {
      throw std::runtime_error("Invalid JSON response");
    }
    
    std::string json_response = response_string.substr(json_start);
    
    // Simple JSON parsing for the result field
    size_t result_pos = json_response.find("\"result\"");
    if (result_pos == std::string::npos) {
      throw std::runtime_error("No result in response");
    }
    
    size_t quote_start = json_response.find("\"0x", result_pos);
    if (quote_start == std::string::npos) {
      throw std::runtime_error("Invalid chain ID format");
    }
    
    size_t quote_end = json_response.find("\"", quote_start + 1);
    if (quote_end == std::string::npos) {
      throw std::runtime_error("Invalid chain ID format");
    }
    
    std::string chain_id_hex = json_response.substr(quote_start + 1, quote_end - quote_start - 1);
    
    // Convert hex to decimal
    if (chain_id_hex.substr(0, 2) == "0x") {
      chain_id_hex = chain_id_hex.substr(2);
    }
    
    return std::stoull(chain_id_hex, nullptr, 16);
  } catch (const std::exception &e) {
    std::cerr << "Warning: Failed to parse chain ID: " << e.what() << std::endl;
    return 31337; // Default to Hardhat
  }
}

} // namespace quip