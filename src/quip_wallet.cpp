#include "../include/quip_wallet.hpp"
#include "../include/common.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

using namespace std;

namespace quip {

class QuipWallet::Impl {
public:
  // QuipWallet ABI (minimal version with just the functions we need)
  static const std::string abi_json;

  Impl(const std::string &rpc_url, const std::string &contract_address)
      : rpc_url_(rpc_url), contract_address_(contract_address) {
    curl_global_init(CURL_GLOBAL_ALL);
  }

  ~Impl() { curl_global_cleanup(); }

  bool transferWithWinternitz(const WinternitzAddress &winternitz_address,
                              const Signature &pq_sig,
                              const Address &to_address, Amount amount) {
    try {
      // Get private key from environment
      const char *env_private_key = std::getenv("PRIVATE_KEY");
      if (!env_private_key) {
        throw std::runtime_error("PRIVATE_KEY environment variable not set");
      }
      PrivateKey private_key = env_private_key;

      // Convert C++ types to the format expected by the ABI encoder
      nlohmann::json nextPqOwner = {
          {"publicSeed", toHex(winternitz_address.publicSeed)},
          {"publicKeyHash", toHex(winternitz_address.publicKeyHash)}};

      // Convert signature elements to hex strings
      nlohmann::json elements = nlohmann::json::array();
      for (const auto &element : pq_sig) {
        elements.push_back(toHex(element));
      }
      nlohmann::json pqSig = {{"elements", elements}};

      // Create parameters for ABI encoding
      nlohmann::json params = {nextPqOwner, pqSig, to_address,
                               std::to_string(amount)};

      // Encode the function call using shared abiEncode function
      std::string params_json = params.dump();
      std::string data =
          abiEncode("transferWithWinternitz", abi_json, params_json);

      // Get the transfer fee
      Amount transferFee = getTransferFee();

      // Get account address from private key
      std::string from_address = deriveClassicalPublicKey(private_key);

      // Get nonce
      nlohmann::json nonce_params = {from_address, "latest"};
      auto nonce_response =
          sendJsonRpc("eth_getTransactionCount", nonce_params);
      std::string nonce_hex = nonce_response["result"];
      uint64_t nonce = std::stoull(nonce_hex.substr(2), nullptr, 16);

      // Get gas price and convert to EIP-1559 format
      auto gas_price_response =
          sendJsonRpc("eth_gasPrice", nlohmann::json::array());
      std::string gas_price_hex = gas_price_response["result"];
      uint64_t gas_price = std::stoull(gas_price_hex.substr(2), nullptr, 16);

      uint64_t max_fee_per_gas = gas_price * 2;
      uint64_t max_priority_fee_per_gas = gas_price;

      std::stringstream max_fee_ss;
      max_fee_ss << "0x" << std::hex << max_fee_per_gas;
      std::string max_fee_hex = max_fee_ss.str();

      std::stringstream max_priority_ss;
      max_priority_ss << "0x" << std::hex << max_priority_fee_per_gas;
      std::string max_priority_hex = max_priority_ss.str();

      // Estimate gas
      uint64_t gas_limit = 500000; // Use a reasonable gas limit
      try {
        nlohmann::json call_object = {
            {"from", from_address},
            {"to", contract_address_},
            {"data", data},
            {"value", "0x" + std::to_string(transferFee)}};
        nlohmann::json estimate_params = {call_object, "latest"};
        auto gas_response = sendJsonRpc("eth_estimateGas", estimate_params);
        if (!gas_response["result"].is_null()) {
          std::string gas_estimate_hex = gas_response["result"];
          uint64_t gas_estimate =
              std::stoull(gas_estimate_hex.substr(2), nullptr, 16);
          gas_limit = gas_estimate + 50000; // Add 50K gas buffer
        }
      } catch (const std::exception &e) {
        // If gas estimation fails, use the fallback gas limit
        std::cerr << "Debug: Gas estimation failed, using fallback: "
                  << e.what() << std::endl;
      }

      // Convert values to hex strings
      std::stringstream gas_ss;
      gas_ss << "0x" << std::hex << gas_limit;
      std::string gas_hex = gas_ss.str();

      std::stringstream nonce_ss;
      nonce_ss << "0x" << std::hex << nonce;
      std::string nonce_hex_str = nonce_ss.str();

      std::stringstream value_ss;
      value_ss << "0x" << std::hex << transferFee;
      std::string value_hex = value_ss.str();

      // Create transaction
      nlohmann::json tx = {{"from", from_address},
                           {"to", contract_address_},
                           {"data", data},
                           {"value", value_hex},
                           {"gas", gas_hex},
                           {"maxFeePerGas", max_fee_hex},
                           {"maxPriorityFeePerGas", max_priority_hex},
                           {"nonce", nonce_hex_str},
                           {"chainId", 31337}};

      // Send transaction using the TypeScript script
      std::string tx_json = tx.dump();

      // Escape quotes in the JSON for shell command
      std::string escaped_tx_json = tx_json;
      size_t pos = 0;
      while ((pos = escaped_tx_json.find("\"", pos)) != std::string::npos) {
        escaped_tx_json.replace(pos, 1, "\\\"");
        pos += 2;
      }

      // Escape the private key for shell command
      std::string escaped_private_key = private_key;
      pos = 0;
      while ((pos = escaped_private_key.find("\"", pos)) != std::string::npos) {
        escaped_private_key.replace(pos, 1, "\\\"");
        pos += 2;
      }

      std::string command = std::string("cd ./ethereum-sdk/scripts && npx "
                                        "ts-node sendTransaction.ts \"") +
                            escaped_tx_json + "\" \"" + escaped_private_key +
                            "\"";

      // Debug output
      std::cerr << "Debug: Private key: " << private_key << std::endl;
      std::cerr << "Debug: Escaped private key: " << escaped_private_key
                << std::endl;
      std::cerr << "Debug: Command: " << command << std::endl;

      FILE *pipe = popen(command.c_str(), "r");
      if (!pipe) {
        throw std::runtime_error("Failed to execute transaction script");
      }

      std::string result;
      char buffer[128];
      while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
      }
      pclose(pipe);

      // Remove newlines
      while (!result.empty() &&
             (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
      }

      // Check if the script failed
      if (result.find("Error:") != std::string::npos) {
        throw std::runtime_error("Transaction failed: " + result);
      }

      // Parse the transaction hash
      std::istringstream result_stream(result);
      std::string tx_hash;

      if (std::getline(result_stream, tx_hash)) {
        std::cerr << "Debug: Transfer transaction hash: " << tx_hash
                  << std::endl;
        return true;
      } else {
        throw std::runtime_error("Failed to parse transaction result: " +
                                 result);
      }
    } catch (const std::exception &e) {
      std::cerr << "Error in transferWithWinternitz: " << e.what() << std::endl;
      return false;
    }
  }

  bool executeWithWinternitz(const WinternitzAddress &winternitz_address,
                             const Signature &pq_sig,
                             const Address &target_address,
                             const std::vector<uint8_t> &opdata) {
    try {
      // Get private key from environment
      const char *env_private_key = std::getenv("PRIVATE_KEY");
      if (!env_private_key) {
        throw std::runtime_error("PRIVATE_KEY environment variable not set");
      }
      PrivateKey private_key = env_private_key;

      // Convert C++ types to the format expected by the ABI encoder
      nlohmann::json nextPqOwner = {
          {"publicSeed", toHex(winternitz_address.publicSeed)},
          {"publicKeyHash", toHex(winternitz_address.publicKeyHash)}};

      // Convert signature elements to hex strings
      nlohmann::json elements = nlohmann::json::array();
      for (const auto &element : pq_sig) {
        elements.push_back(toHex(element));
      }
      nlohmann::json pqSig = {{"elements", elements}};

      // Convert opdata to hex string
      std::string opdata_hex = toHex(opdata);

      // Create parameters for ABI encoding
      nlohmann::json params = {nextPqOwner, pqSig, target_address, opdata_hex};

      // Encode the function call using shared abiEncode function
      std::string params_json = params.dump();
      std::string data =
          abiEncode("executeWithWinternitz", abi_json, params_json);

      // Get the transfer fee
      Amount transferFee = getTransferFee();

      // Get account address from private key
      std::string from_address = deriveClassicalPublicKey(private_key);

      // Get nonce
      nlohmann::json nonce_params = {from_address, "latest"};
      auto nonce_response =
          sendJsonRpc("eth_getTransactionCount", nonce_params);
      std::string nonce_hex = nonce_response["result"];
      uint64_t nonce = std::stoull(nonce_hex.substr(2), nullptr, 16);

      // Get gas price and convert to EIP-1559 format
      auto gas_price_response =
          sendJsonRpc("eth_gasPrice", nlohmann::json::array());
      std::string gas_price_hex = gas_price_response["result"];
      uint64_t gas_price = std::stoull(gas_price_hex.substr(2), nullptr, 16);

      uint64_t max_fee_per_gas = gas_price * 2;
      uint64_t max_priority_fee_per_gas = gas_price;

      std::stringstream max_fee_ss;
      max_fee_ss << "0x" << std::hex << max_fee_per_gas;
      std::string max_fee_hex = max_fee_ss.str();

      std::stringstream max_priority_ss;
      max_priority_ss << "0x" << std::hex << max_priority_fee_per_gas;
      std::string max_priority_hex = max_priority_ss.str();

      // Estimate gas
      uint64_t gas_limit = 500000; // Use a reasonable gas limit
      try {
        nlohmann::json call_object = {
            {"from", from_address},
            {"to", contract_address_},
            {"data", data},
            {"value", "0x" + std::to_string(transferFee)}};
        nlohmann::json estimate_params = {call_object, "latest"};
        auto gas_response = sendJsonRpc("eth_estimateGas", estimate_params);
        if (!gas_response["result"].is_null()) {
          std::string gas_estimate_hex = gas_response["result"];
          uint64_t gas_estimate =
              std::stoull(gas_estimate_hex.substr(2), nullptr, 16);
          gas_limit = gas_estimate + 50000; // Add 50K gas buffer
        }
      } catch (const std::exception &e) {
        // If gas estimation fails, use the fallback gas limit
        std::cerr << "Debug: Gas estimation failed, using fallback: "
                  << e.what() << std::endl;
      }

      // Convert values to hex strings
      std::stringstream gas_ss;
      gas_ss << "0x" << std::hex << gas_limit;
      std::string gas_hex = gas_ss.str();

      std::stringstream nonce_ss;
      nonce_ss << "0x" << std::hex << nonce;
      std::string nonce_hex_str = nonce_ss.str();

      std::stringstream value_ss;
      value_ss << "0x" << std::hex << transferFee;
      std::string value_hex = value_ss.str();

      // Create transaction
      nlohmann::json tx = {{"from", from_address},
                           {"to", contract_address_},
                           {"data", data},
                           {"value", value_hex},
                           {"gas", gas_hex},
                           {"maxFeePerGas", max_fee_hex},
                           {"maxPriorityFeePerGas", max_priority_hex},
                           {"nonce", nonce_hex_str},
                           {"chainId", 31337}};

      // Send transaction using the TypeScript script
      std::string tx_json = tx.dump();

      // Escape quotes in the JSON for shell command
      std::string escaped_tx_json = tx_json;
      size_t pos = 0;
      while ((pos = escaped_tx_json.find("\"", pos)) != std::string::npos) {
        escaped_tx_json.replace(pos, 1, "\\\"");
        pos += 2;
      }

      // Escape the private key for shell command
      std::string escaped_private_key = private_key;
      pos = 0;
      while ((pos = escaped_private_key.find("\"", pos)) != std::string::npos) {
        escaped_private_key.replace(pos, 1, "\\\"");
        pos += 2;
      }

      std::string command = std::string("cd ./ethereum-sdk/scripts && npx "
                                        "ts-node sendTransaction.ts \"") +
                            escaped_tx_json + "\" \"" + escaped_private_key +
                            "\"";

      // Debug output
      std::cerr << "Debug: Private key: " << private_key << std::endl;
      std::cerr << "Debug: Escaped private key: " << escaped_private_key
                << std::endl;
      std::cerr << "Debug: Command: " << command << std::endl;

      FILE *pipe = popen(command.c_str(), "r");
      if (!pipe) {
        throw std::runtime_error("Failed to execute transaction script");
      }

      std::string result;
      char buffer[128];
      while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
      }
      pclose(pipe);

      // Remove newlines
      while (!result.empty() &&
             (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
      }

      // Check if the script failed
      if (result.find("Error:") != std::string::npos) {
        throw std::runtime_error("Transaction failed: " + result);
      }

      // Parse the transaction hash
      std::istringstream result_stream(result);
      std::string tx_hash;

      if (std::getline(result_stream, tx_hash)) {
        std::cerr << "Debug: Execute transaction hash: " << tx_hash
                  << std::endl;
        return true;
      } else {
        throw std::runtime_error("Failed to parse transaction result: " +
                                 result);
      }
    } catch (const std::exception &e) {
      std::cerr << "Error in executeWithWinternitz: " << e.what() << std::endl;
      return false;
    }
  }

  bool changePqOwner(const WinternitzAddress &winternitz_address,
                     const Signature &pq_sig) {
    try {
      // Get private key from environment
      const char *env_private_key = std::getenv("PRIVATE_KEY");
      if (!env_private_key) {
        throw std::runtime_error("PRIVATE_KEY environment variable not set");
      }
      PrivateKey private_key = env_private_key;

      // Convert C++ types to the format expected by the ABI encoder
      nlohmann::json newPqOwner = {
          {"publicSeed", toHex(winternitz_address.publicSeed)},
          {"publicKeyHash", toHex(winternitz_address.publicKeyHash)}};

      // Convert signature elements to hex strings
      nlohmann::json elements = nlohmann::json::array();
      for (const auto &element : pq_sig) {
        elements.push_back(toHex(element));
      }
      nlohmann::json pqSig = {{"elements", elements}};

      // Create parameters for ABI encoding
      nlohmann::json params = {newPqOwner, pqSig};

      // Encode the function call using shared abiEncode function
      std::string params_json = params.dump();
      std::string data = abiEncode("changePqOwner", abi_json, params_json);

      // Get the transfer fee
      Amount transferFee = getTransferFee();

      // Get account address from private key
      std::string from_address = deriveClassicalPublicKey(private_key);

      // Get nonce
      nlohmann::json nonce_params = {from_address, "latest"};
      auto nonce_response =
          sendJsonRpc("eth_getTransactionCount", nonce_params);
      std::string nonce_hex = nonce_response["result"];
      uint64_t nonce = std::stoull(nonce_hex.substr(2), nullptr, 16);

      // Get gas price and convert to EIP-1559 format
      auto gas_price_response =
          sendJsonRpc("eth_gasPrice", nlohmann::json::array());
      std::string gas_price_hex = gas_price_response["result"];
      uint64_t gas_price = std::stoull(gas_price_hex.substr(2), nullptr, 16);

      uint64_t max_fee_per_gas = gas_price * 2;
      uint64_t max_priority_fee_per_gas = gas_price;

      std::stringstream max_fee_ss;
      max_fee_ss << "0x" << std::hex << max_fee_per_gas;
      std::string max_fee_hex = max_fee_ss.str();

      std::stringstream max_priority_ss;
      max_priority_ss << "0x" << std::hex << max_priority_fee_per_gas;
      std::string max_priority_hex = max_priority_ss.str();

      // Estimate gas
      uint64_t gas_limit = 500000; // Use a reasonable gas limit
      try {
        nlohmann::json call_object = {
            {"from", from_address},
            {"to", contract_address_},
            {"data", data},
            {"value", "0x" + std::to_string(transferFee)}};
        nlohmann::json estimate_params = {call_object, "latest"};
        auto gas_response = sendJsonRpc("eth_estimateGas", estimate_params);
        if (!gas_response["result"].is_null()) {
          std::string gas_estimate_hex = gas_response["result"];
          uint64_t gas_estimate =
              std::stoull(gas_estimate_hex.substr(2), nullptr, 16);
          gas_limit = gas_estimate + 50000; // Add 50K gas buffer
        }
      } catch (const std::exception &e) {
        // If gas estimation fails, use the fallback gas limit
        std::cerr << "Debug: Gas estimation failed, using fallback: "
                  << e.what() << std::endl;
      }

      // Convert values to hex strings
      std::stringstream gas_ss;
      gas_ss << "0x" << std::hex << gas_limit;
      std::string gas_hex = gas_ss.str();

      std::stringstream nonce_ss;
      nonce_ss << "0x" << std::hex << nonce;
      std::string nonce_hex_str = nonce_ss.str();

      std::stringstream value_ss;
      value_ss << "0x" << std::hex << transferFee;
      std::string value_hex = value_ss.str();

      // Create transaction
      nlohmann::json tx = {{"from", from_address},
                           {"to", contract_address_},
                           {"data", data},
                           {"value", value_hex},
                           {"gas", gas_hex},
                           {"maxFeePerGas", max_fee_hex},
                           {"maxPriorityFeePerGas", max_priority_hex},
                           {"nonce", nonce_hex_str},
                           {"chainId", 31337}};

      // Send transaction using the TypeScript script
      std::string tx_json = tx.dump();

      // Escape quotes in the JSON for shell command
      std::string escaped_tx_json = tx_json;
      size_t pos = 0;
      while ((pos = escaped_tx_json.find("\"", pos)) != std::string::npos) {
        escaped_tx_json.replace(pos, 1, "\\\"");
        pos += 2;
      }

      // Escape the private key for shell command
      std::string escaped_private_key = private_key;
      pos = 0;
      while ((pos = escaped_private_key.find("\"", pos)) != std::string::npos) {
        escaped_private_key.replace(pos, 1, "\\\"");
        pos += 2;
      }

      std::string command = std::string("cd ./ethereum-sdk/scripts && npx "
                                        "ts-node sendTransaction.ts \"") +
                            escaped_tx_json + "\" \"" + escaped_private_key +
                            "\"";

      // Debug output
      std::cerr << "Debug: Private key: " << private_key << std::endl;
      std::cerr << "Debug: Escaped private key: " << escaped_private_key
                << std::endl;
      std::cerr << "Debug: Command: " << command << std::endl;

      FILE *pipe = popen(command.c_str(), "r");
      if (!pipe) {
        throw std::runtime_error("Failed to execute transaction script");
      }

      std::string result;
      char buffer[128];
      while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
      }
      pclose(pipe);

      // Remove newlines
      while (!result.empty() &&
             (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
      }

      // Check if the script failed
      if (result.find("Error:") != std::string::npos) {
        throw std::runtime_error("Transaction failed: " + result);
      }

      // Parse the transaction hash
      std::istringstream result_stream(result);
      std::string tx_hash;

      if (std::getline(result_stream, tx_hash)) {
        std::cerr << "Debug: Change PQ owner transaction hash: " << tx_hash
                  << std::endl;
        return true;
      } else {
        throw std::runtime_error("Failed to parse transaction result: " +
                                 result);
      }
    } catch (const std::exception &e) {
      std::cerr << "Error in changePqOwner: " << e.what() << std::endl;
      return false;
    }
  }

  Address getPqOwner() {
    try {
      // Encode the function call for pqOwner (no params)
      nlohmann::json params = nlohmann::json::array();
      std::string params_json = params.dump();
      std::string data = abiEncode("pqOwner", abi_json, params_json);

      // Create call object
      nlohmann::json call_object = {{"to", contract_address_}, {"data", data}};
      nlohmann::json call_params = {call_object, "latest"};

      // Make the call
      auto response = sendJsonRpc("eth_call", call_params);
      std::string result = response["result"];

      // Decode the result: two 32-byte values (publicSeed, publicKeyHash)
      if (result.length() == 2 + 64 + 64) { // 0x + 64 + 64 hex chars
        std::string publicSeed = result.substr(2, 64);
        std::string publicKeyHash = result.substr(66, 64);
        return "0x" + publicSeed + publicKeyHash;
      }
      return "0x";
    } catch (const std::exception &e) {
      std::cerr << "Error in getPqOwner: " << e.what() << std::endl;
      return "0x";
    }
  }

  Amount getBalance() {
    try {
      // Use eth_getBalance on the contract address
      nlohmann::json params = {contract_address_, "latest"};
      auto response = sendJsonRpc("eth_getBalance", params);
      std::string result = response["result"];
      if (result.length() > 2) {
        return std::stoull(result.substr(2), nullptr, 16);
      }
      return 0;
    } catch (const std::exception &e) {
      std::cerr << "Error in getBalance: " << e.what() << std::endl;
      return 0;
    }
  }

  // Get transfer fee from contract
  Amount getTransferFee() {
    try {
      // Call the contract to get transfer fee
      nlohmann::json params = {contract_address_, "0x", "latest"};
      auto response = sendJsonRpc("eth_call", params);
      // For now, return a default fee
      return 1000000000000000; // 0.001 ETH in wei
    } catch (const std::exception &e) {
      // Return default fee if call fails
      return 1000000000000000; // 0.001 ETH in wei
    }
  }

  // Derive classical public key from private key
  std::string deriveClassicalPublicKey(const PrivateKey &private_key) {
    // Use the same approach as CLI - call ethers.js from ethereum-sdk
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
      throw std::runtime_error("ethers.js command failed");
    }

    // Remove newline and return the address
    if (!result.empty() && result[result.length() - 1] == '\n') {
      result.erase(result.length() - 1);
    }

    return result;
  }

  std::string getRecipientAddress() const {
    return "0x742d35cc6634c0532925a3b8d4c9db96c4b4d8b6";
  }

private:
  static size_t WriteCallback(void *contents, size_t size, size_t nmemb,
                              std::string *userp) {
    userp->append((char *)contents, size * nmemb);
    return size * nmemb;
  }

  nlohmann::json sendJsonRpc(const std::string &method,
                             const nlohmann::json &params) {
    CURL *curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }

    nlohmann::json request = {
        {"jsonrpc", "2.0"}, {"id", 1}, {"method", method}, {"params", params}};

    std::string response_string;
    std::string request_string = request.dump();

    curl_easy_setopt(curl, CURLOPT_URL, rpc_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_string.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
      throw std::runtime_error("CURL request failed: " +
                               std::string(curl_easy_strerror(res)));
    }

    auto response = nlohmann::json::parse(response_string);
    if (response.contains("error")) {
      throw std::runtime_error("JSON-RPC error: " +
                               response["error"]["message"].get<std::string>());
    }

    return response;
  }

  std::string rpc_url_;
  std::string contract_address_;
};

QuipWallet::QuipWallet(const std::string &rpc_url,
                       const std::string &contract_address)
    : impl_(std::make_unique<Impl>(rpc_url, contract_address)) {}

QuipWallet::~QuipWallet() = default;

bool QuipWallet::transferWithWinternitz(
    const WinternitzAddress &winternitz_address, const Signature &pq_sig,
    const Address &to_address, Amount amount) {
  return impl_->transferWithWinternitz(winternitz_address, pq_sig, to_address,
                                       amount);
}

bool QuipWallet::executeWithWinternitz(
    const WinternitzAddress &winternitz_address, const Signature &pq_sig,
    const Address &target_address, const std::vector<uint8_t> &opdata) {
  return impl_->executeWithWinternitz(winternitz_address, pq_sig,
                                      target_address, opdata);
}

bool QuipWallet::changePqOwner(const WinternitzAddress &winternitz_address,
                               const Signature &pq_sig) {
  return impl_->changePqOwner(winternitz_address, pq_sig);
}

Address QuipWallet::getPqOwner() { return impl_->getPqOwner(); }

Amount QuipWallet::getBalance() { return impl_->getBalance(); }

// Define the static member
const std::string QuipWallet::Impl::abi_json =
    R"([{ "inputs": [ { "internalType": "address payable", "name": "creator", "type": "address" }, { "internalType": "address payable", "name": "newOwner", "type": "address" } ], "stateMutability": "payable", "type": "constructor" }, { "anonymous": false, "inputs": [ { "indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256" }, { "indexed": false, "internalType": "uint256", "name": "when", "type": "uint256" }, { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "indexed": false, "internalType": "struct WOTSPlus.WinternitzAddress", "name": "pqFrom", "type": "tuple" }, { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "indexed": false, "internalType": "struct WOTSPlus.WinternitzAddress", "name": "pqNext", "type": "tuple" }, { "indexed": false, "internalType": "address", "name": "to", "type": "address" } ], "name": "pqTransfer", "type": "event" }, { "stateMutability": "payable", "type": "fallback" }, { "inputs": [ { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "internalType": "struct WOTSPlus.WinternitzAddress", "name": "newPqOwner", "type": "tuple" }, { "components": [ { "internalType": "bytes32[67]", "name": "elements", "type": "bytes32[67]" } ], "internalType": "struct WOTSPlus.WinternitzElements", "name": "pqSig", "type": "tuple" } ], "name": "changePqOwner", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "internalType": "struct WOTSPlus.WinternitzAddress", "name": "nextPqOwner", "type": "tuple" }, { "components": [ { "internalType": "bytes32[67]", "name": "elements", "type": "bytes32[67]" } ], "internalType": "struct WOTSPlus.WinternitzElements", "name": "pqSig", "type": "tuple" }, { "internalType": "address payable", "name": "target", "type": "address" }, { "internalType": "bytes", "name": "opdata", "type": "bytes" } ], "name": "executeWithWinternitz", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" }, { "internalType": "bytes", "name": "", "type": "bytes" } ], "stateMutability": "payable", "type": "function" }, { "inputs": [], "name": "getExecuteFee", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "getTransferFee", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "internalType": "struct WOTSPlus.WinternitzAddress", "name": "newPqOwner", "type": "tuple" } ], "name": "initialize", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [], "name": "owner", "outputs": [ { "internalType": "address payable", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "pqOwner", "outputs": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "stateMutability": "view", "type": "function" }, { "inputs": [], "name": "quipFactory", "outputs": [ { "internalType": "address payable", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" }, { "inputs": [ { "components": [ { "internalType": "bytes32", "name": "publicSeed", "type": "bytes32" }, { "internalType": "bytes32", "name": "publicKeyHash", "type": "bytes32" } ], "internalType": "struct WOTSPlus.WinternitzAddress", "name": "nextPqOwner", "type": "tuple" }, { "components": [ { "internalType": "bytes32[67]", "name": "elements", "type": "bytes32[67]" } ], "internalType": "struct WOTSPlus.WinternitzElements", "name": "pqSig", "type": "tuple" }, { "internalType": "address payable", "name": "to", "type": "address" }, { "internalType": "uint256", "name": "value", "type": "uint256" } ], "name": "transferWithWinternitz", "outputs": [], "stateMutability": "payable", "type": "function" }, { "stateMutability": "payable", "type": "receive" }])";

} // namespace quip