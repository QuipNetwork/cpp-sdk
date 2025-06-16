#include "quip_wallet.hpp"
#include "common.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

namespace quip {

class QuipWallet::Impl {
public:
  Impl(const std::string &rpc_url, const std::string &contract_address)
      : rpc_url_(rpc_url), contract_address_(contract_address) {
    curl_global_init(CURL_GLOBAL_ALL);
  }

  ~Impl() { curl_global_cleanup(); }

  bool transferWithWinternitz(const PublicKey &pq_pubkey,
                              const Signature &pq_sig,
                              const Address &to_address, Amount amount,
                              const PrivateKey &private_key) {
    // TODO: Implement actual logic
    return true;
  }

  bool executeWithWinternitz(const PublicKey &pq_pubkey,
                             const Signature &pq_sig,
                             const Address &target_address,
                             const std::vector<uint8_t> &opdata,
                             const PrivateKey &private_key) {
    // TODO: Implement actual logic
    return true;
  }

  bool changePqOwner(const PublicKey &pq_pubkey, const Signature &pq_sig,
                     const PrivateKey &private_key) {
    // TODO: Implement actual logic
    return true;
  }

  Address getPqOwner() {
    // TODO: Implement actual logic
    return "0x0000000000000000000000000000000000000000";
  }

  Amount getBalance() {
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

  std::string encodeTransferWithWinternitz(
      const hashsigs::PublicKey &next_pq_owner,
      const std::vector<std::array<uint8_t, 32>> &pq_sig,
      const std::string &to_address, uint64_t value_wei) {
    // TODO: Implement ABI encoding for transferWithWinternitz
    return "";
  }

  std::string encodeExecuteWithWinternitz(
      const hashsigs::PublicKey &next_pq_owner,
      const std::vector<std::array<uint8_t, 32>> &pq_sig,
      const std::string &target_address, const std::vector<uint8_t> &opdata) {
    // TODO: Implement ABI encoding for executeWithWinternitz
    return "";
  }

  std::string
  encodeChangePqOwner(const hashsigs::PublicKey &new_pq_owner,
                      const std::vector<std::array<uint8_t, 32>> &pq_sig) {
    // TODO: Implement ABI encoding for changePqOwner
    return "";
  }

  std::string rpc_url_;
  std::string contract_address_;
};

QuipWallet::QuipWallet(const std::string &rpc_url,
                       const std::string &contract_address)
    : impl_(std::make_unique<Impl>(rpc_url, contract_address)) {}

QuipWallet::~QuipWallet() = default;

bool QuipWallet::transferWithWinternitz(const PublicKey &pq_pubkey,
                                        const Signature &pq_sig,
                                        const Address &to_address,
                                        Amount amount,
                                        const PrivateKey &private_key) {
  return impl_->transferWithWinternitz(pq_pubkey, pq_sig, to_address, amount,
                                       private_key);
}

bool QuipWallet::executeWithWinternitz(const PublicKey &pq_pubkey,
                                       const Signature &pq_sig,
                                       const Address &target_address,
                                       const std::vector<uint8_t> &opdata,
                                       const PrivateKey &private_key) {
  return impl_->executeWithWinternitz(pq_pubkey, pq_sig, target_address, opdata,
                                      private_key);
}

bool QuipWallet::changePqOwner(const PublicKey &pq_pubkey,
                               const Signature &pq_sig,
                               const PrivateKey &private_key) {
  return impl_->changePqOwner(pq_pubkey, pq_sig, private_key);
}

Address QuipWallet::getPqOwner() { return impl_->getPqOwner(); }

Amount QuipWallet::getBalance() { return impl_->getBalance(); }

} // namespace quip