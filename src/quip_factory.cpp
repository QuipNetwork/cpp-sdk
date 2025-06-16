#include "quip_factory.hpp"
#include "common.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

namespace quip {

class QuipFactory::Impl {
public:
  Impl(const std::string &rpc_url, const std::string &contract_address)
      : rpc_url_(rpc_url), contract_address_(contract_address) {
    curl_global_init(CURL_GLOBAL_ALL);
  }

  ~Impl() { curl_global_cleanup(); }

  bool depositToWinternitz(const PublicKey &pq_pubkey, const Signature &pq_sig,
                           const PrivateKey &private_key) {
    // TODO: Implement actual logic
    // For now, just return true as a stub
    return true;
  }

  Address getQuipWalletAddress(const PublicKey &pq_pubkey) {
    // TODO: Implement actual logic
    // For now, just return a stub address
    return "0x0000000000000000000000000000000000000000";
  }

  Amount getCreationFee() {
    // TODO: Implement actual logic
    return 0;
  }

  Amount getTransferFee() {
    // TODO: Implement actual logic
    return 0;
  }

  Amount getExecuteFee() {
    // TODO: Implement actual logic
    return 0;
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

  std::string encodeDepositToWinternitz(const std::array<uint8_t, 32> &vault_id,
                                        const std::string &to_address,
                                        const hashsigs::PublicKey &pq_to) {
    // TODO: Implement ABI encoding for depositToWinternitz
    return "";
  }

  std::string
  encodeGetQuipWalletAddress(const std::array<uint8_t, 32> &vault_id,
                             const std::string &owner_address) {
    // TODO: Implement ABI encoding for getQuipWalletAddress
    return "";
  }

  std::string rpc_url_;
  std::string contract_address_;
};

QuipFactory::QuipFactory(const std::string &rpc_url,
                         const std::string &contract_address)
    : impl_(std::make_unique<Impl>(rpc_url, contract_address)) {}

QuipFactory::~QuipFactory() = default;

bool QuipFactory::depositToWinternitz(const PublicKey &pq_pubkey,
                                      const Signature &pq_sig,
                                      const PrivateKey &private_key) {
  return impl_->depositToWinternitz(pq_pubkey, pq_sig, private_key);
}

Address QuipFactory::getQuipWalletAddress(const PublicKey &pq_pubkey) {
  return impl_->getQuipWalletAddress(pq_pubkey);
}

Amount QuipFactory::getCreationFee() { return impl_->getCreationFee(); }
Amount QuipFactory::getTransferFee() { return impl_->getTransferFee(); }
Amount QuipFactory::getExecuteFee() { return impl_->getExecuteFee(); }

} // namespace quip