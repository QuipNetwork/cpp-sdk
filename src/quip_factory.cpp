#include "quip_factory.hpp"
#include "common.hpp"
#include <algorithm>
#include <chrono>
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace quip {

// Helper function to ensure a string has a single '0x' prefix
static std::string ensure0x(const std::string &hex) {
  if (hex.rfind("0x", 0) == 0)
    return hex;
  return "0x" + hex;
}

class QuipFactory::Impl {
public:
  // QuipFactory ABI (minimal version with just the functions we need)
  static const std::string abi_json;

  Impl(const std::string &rpc_url, const std::string &contract_address)
      : rpc_url_(rpc_url), contract_address_(contract_address) {
    curl_global_init(CURL_GLOBAL_ALL);
  }

  ~Impl() { curl_global_cleanup(); }

  Address depositToWinternitz(const VaultId &vaultId, const Address &to,
                              const WinternitzAddress &pqTo,
                              const PrivateKey &private_key,
                              const Amount &amount) {
    // Encode the function call using the ABI encoding script
    nlohmann::json params = {
        toHex(vaultId),
        to,
        {toHex(pqTo.publicSeed), toHex(pqTo.publicKeyHash)}};

    std::string params_json = params.dump();
    std::string data = abiEncode("depositToWinternitz", abi_json, params_json);

    // Get the nonce for the account
    const char *env_private_key = std::getenv("PRIVATE_KEY");
    if (!env_private_key) {
      throw std::runtime_error("PRIVATE_KEY environment variable not set");
    }

    // Get account address from private key using ethers.js
    std::string command =
        std::string("cd ./ethereum-sdk && node -e \"console.log(new "
                    "(require('ethers').Wallet)('") +
        env_private_key + "').address)\"";

    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
      throw std::runtime_error("Failed to execute ethers.js command");
    }

    std::string from_address;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
      from_address += buffer;
    }
    int status = pclose(pipe);
    if (status != 0) {
      throw std::runtime_error("ethers.js command failed: " + from_address);
    }

    // Remove newline
    if (!from_address.empty() &&
        from_address[from_address.length() - 1] == '\n') {
      from_address.erase(from_address.length() - 1);
    }

    // Get nonce
    nlohmann::json nonce_params = {from_address, "latest"};
    auto nonce_response = sendJsonRpc("eth_getTransactionCount", nonce_params);
    std::string nonce_hex = nonce_response["result"];
    uint64_t nonce = std::stoull(nonce_hex.substr(2), nullptr, 16);

    // Get gas price and convert to EIP-1559 format
    auto gas_price_response =
        sendJsonRpc("eth_gasPrice", nlohmann::json::array());
    std::string gas_price_hex = gas_price_response["result"];
    uint64_t gas_price = std::stoull(gas_price_hex.substr(2), nullptr, 16);

    // For EIP-1559, set maxFeePerGas to 2x gas price and maxPriorityFeePerGas
    // to gas price
    uint64_t max_fee_per_gas = gas_price * 2;
    uint64_t max_priority_fee_per_gas = gas_price;

    // Convert to hex strings
    std::stringstream max_fee_ss;
    max_fee_ss << std::hex << max_fee_per_gas;
    std::string max_fee_hex = ensure0x(max_fee_ss.str());

    std::stringstream max_priority_ss;
    max_priority_ss << std::hex << max_priority_fee_per_gas;
    std::string max_priority_hex = ensure0x(max_priority_ss.str());

    std::stringstream ss;
    ss << std::hex << amount;
    std::string value_hex = ensure0x(ss.str());

    // Estimate gas
    // Try to estimate gas, but use a reasonable fallback if it fails
    uint64_t gas_limit = 1800000; // Use a reasonable gas limit of 1.800M gas
    try {
      nlohmann::json call_object = {{"from", from_address},
                                    {"to", contract_address_},
                                    {"data", data},
                                    {"value", value_hex}};
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
    }

    // Convert gas limit to hex string
    std::stringstream gas_ss;
    gas_ss << std::hex << gas_limit;
    std::string gas_hex = ensure0x(gas_ss.str());

    // Convert nonce to hex string
    std::stringstream nonce_ss;
    nonce_ss << std::hex << nonce;
    std::string nonce_hex_str = ensure0x(nonce_ss.str());

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

    std::string tx_command = std::string("cd ./ethereum-sdk/scripts && npx "
                                         "ts-node sendTransaction.ts \"") +
                             escaped_tx_json + "\"";

    FILE *tx_pipe = popen(tx_command.c_str(), "r");
    if (!tx_pipe) {
      throw std::runtime_error("Failed to execute transaction script");
    }

    std::string result;
    char tx_buffer[128];
    while (fgets(tx_buffer, sizeof(tx_buffer), tx_pipe) != nullptr) {
      result += tx_buffer;
    }
    int tx_status = pclose(tx_pipe);
    if (tx_status != 0) {
      throw std::runtime_error("Transaction script failed with status " +
                               std::to_string(tx_status) + ": " + result);
    }

    // Remove newlines
    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r')) {
      result.pop_back();
    }

    // Check if the script failed
    if (result.find("Error:") != std::string::npos) {
      throw std::runtime_error("Transaction failed: " + result);
    }

    // The script should output the transaction hash on the first line and
    // wallet address on the second line
    std::istringstream result_stream(result);
    std::string tx_hash, wallet_address;

    if (std::getline(result_stream, tx_hash) &&
        std::getline(result_stream, wallet_address)) {
      return wallet_address;
    } else {
      throw std::runtime_error("Failed to parse transaction result: " + result);
    }
  }

  Address getQuipWalletAddress(const VaultId &vaultId, const Address &to) {
    // Encode the function call using the ABI encoding script
    nlohmann::json params = {to, toHex(vaultId)};
    std::string params_json = params.dump();
    std::string data = abiEncode("quips", abi_json, params_json);

    // Call the contract - eth_call expects [call_object, block]
    nlohmann::json call_object = {{"to", contract_address_}, {"data", data}};
    nlohmann::json params_call = {call_object, "latest"};

    auto response = sendJsonRpc("eth_call", params_call);
    std::string result = response["result"];

    // Decode the result (remove 0x prefix and extract the address)
    if (result.length() >= 66) { // 0x + 64 hex chars
      std::string address_hex = "0x" + result.substr(result.length() - 40);
      return address_hex;
    }

    return "0x0000000000000000000000000000000000000000";
  }

  Amount getCreationFee() {
    // Call the contract's creationFee() getter
    nlohmann::json params = nlohmann::json::array();
    std::string params_json = params.dump();
    std::string data = abiEncode("creationFee", abi_json, params_json);
    nlohmann::json call_object = {{"to", contract_address_}, {"data", data}};
    nlohmann::json params_call = {call_object, "latest"};
    auto response = sendJsonRpc("eth_call", params_call);
    std::string result = response["result"];
    if (result.length() >= 66) { // 0x + 64 hex chars
      // Parse uint256 from hex
      return std::stoull(result.substr(2), nullptr, 16);
    }
    return 0;
  }

  Amount getTransferFee() {
    // Call the contract's transferFee() getter
    nlohmann::json params = nlohmann::json::array();
    std::string params_json = params.dump();
    std::string data = abiEncode("transferFee", abi_json, params_json);
    nlohmann::json call_object = {{"to", contract_address_}, {"data", data}};
    nlohmann::json params_call = {call_object, "latest"};
    auto response = sendJsonRpc("eth_call", params_call);
    std::string result = response["result"];
    if (result.length() >= 66) {
      return std::stoull(result.substr(2), nullptr, 16);
    }
    return 0;
  }

  Amount getExecuteFee() {
    // Call the contract's executeFee() getter
    nlohmann::json params = nlohmann::json::array();
    std::string params_json = params.dump();
    std::string data = abiEncode("executeFee", abi_json, params_json);
    nlohmann::json call_object = {{"to", contract_address_}, {"data", data}};
    nlohmann::json params_call = {call_object, "latest"};
    auto response = sendJsonRpc("eth_call", params_call);
    std::string result = response["result"];
    if (result.length() >= 66) {
      return std::stoull(result.substr(2), nullptr, 16);
    }
    return 0;
  }

private:
  static size_t WriteCallback(void *contents, size_t size, size_t nmemb,
                              std::string *userp) {
    userp->append((char *)contents, size * nmemb);
    return size * nmemb;
  }

  static int getNextRequestId() {
    static int id = 1;
    return id++;
  }

  nlohmann::json sendJsonRpc(const std::string &method,
                             const nlohmann::json &params) {
    CURL *curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }

    nlohmann::json request = {{"jsonrpc", "2.0"},
                              {"id", getNextRequestId()},
                              {"method", method},
                              {"params", params}};

    std::string response_string;
    std::string request_string = request.dump();

    curl_easy_setopt(curl, CURLOPT_URL, rpc_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_string.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    curl_easy_setopt(
        curl, CURLOPT_HTTPHEADER,
        curl_slist_append(nullptr, "Content-Type: application/json"));

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

QuipFactory::QuipFactory(const std::string &rpc_url,
                         const std::string &contract_address)
    : impl_(std::make_unique<Impl>(rpc_url, contract_address)) {}

QuipFactory::~QuipFactory() = default;

Address QuipFactory::depositToWinternitz(const VaultId &vaultId,
                                         const Address &to,
                                         const WinternitzAddress &pqTo,
                                         const PrivateKey &private_key,
                                         const Amount &amount) {
  return impl_->depositToWinternitz(vaultId, to, pqTo, private_key, amount);
}

Address QuipFactory::getQuipWalletAddress(const VaultId &vaultId,
                                          const Address &to) {
  return impl_->getQuipWalletAddress(vaultId, to);
}

Amount QuipFactory::getCreationFee() { return impl_->getCreationFee(); }
Amount QuipFactory::getTransferFee() { return impl_->getTransferFee(); }
Amount QuipFactory::getExecuteFee() { return impl_->getExecuteFee(); }

// Define the static member
const std::string QuipFactory::Impl::abi_json =
    R"([{"inputs":[{"internalType":"address payable","name":"initialOwner","type":"address"},{"internalType":"address","name":"_wotsLibrary","type":"address"}],"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"when","type":"uint256"},{"indexed":false,"internalType":"bytes32","name":"vaultId","type":"bytes32"},{"indexed":false,"internalType":"address","name":"creator","type":"address"},{"components":[{"internalType":"bytes32","name":"publicSeed","type":"bytes32"},{"internalType":"bytes32","name":"publicKeyHash","type":"bytes32"}],"indexed":false,"internalType":"struct WOTSPlus.WinternitzAddress","name":"pqPubkey","type":"tuple"},{"indexed":false,"internalType":"address","name":"quip","type":"address"}],"name":"QuipCreated","type":"event"},{"stateMutability":"payable","type":"fallback"},{"inputs":[],"name":"admin","outputs":[{"internalType":"address payable","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"creationFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"vaultId","type":"bytes32"},{"internalType":"address payable","name":"to","type":"address"},{"components":[{"internalType":"bytes32","name":"publicSeed","type":"bytes32"},{"internalType":"bytes32","name":"publicKeyHash","type":"bytes32"}],"internalType":"struct WOTSPlus.WinternitzAddress","name":"pqTo","type":"tuple"}],"name":"depositToWinternitz","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"executeFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"quips","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"newFee","type":"uint256"}],"name":"setCreationFee","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"newFee","type":"uint256"}],"name":"setExecuteFee","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"newFee","type":"uint256"}],"name":"setTransferFee","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"transferFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"vaultIds","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"wotsLibrary","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"stateMutability":"payable","type":"receive"}])";

} // namespace quip