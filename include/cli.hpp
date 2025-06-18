#pragma once

#include "common.hpp"
#include "quip_factory.hpp"
#include "quip_wallet.hpp"
#include <functional>
#include <memory>
#include <string>

namespace quip {

class CLI {
public:
  CLI(const std::string &rpc_url, const std::string &contract_address = "");
  ~CLI();

  // Parse and execute commands
  bool execute(const std::vector<std::string> &args);

  // For testing: set a custom wallet factory
  void setWalletFactory(std::function<std::unique_ptr<QuipWallet>(
                            const std::string &, const std::string &)>
                            factory) {
    wallet_factory_ = std::move(factory);
  }

private:
  // Command handlers
  bool handleDeposit(const std::vector<std::string> &args);
  bool handleTransfer(const std::vector<std::string> &args);
  bool handleExecute(const std::vector<std::string> &args);
  bool handleChangeOwner(const std::vector<std::string> &args);
  bool handleGetBalance(const std::vector<std::string> &args);
  bool handleGetPqOwner(const std::vector<std::string> &args);

  // Helper functions
  void printUsage() const;
  std::string getContractAddress(const std::string &contract_name) const;
  std::array<uint8_t, 32> parseVaultId(const std::string &vault_id) const;
  Address parseAddress(const std::string &address) const;
  Amount parseAmount(const std::string &amount) const;
  std::vector<uint8_t> parseOpData(const std::string &opdata) const;
  std::vector<uint8_t> parsePublicKey(const std::string &pubkey) const;
  std::vector<uint8_t> parseSignature(const std::string &sig) const;
  std::vector<uint8_t> parsePrivateKey(const std::string &key) const;

  // Create a wallet instance
  std::unique_ptr<QuipWallet> createWallet(const std::string &address) {
    if (wallet_factory_) {
      return wallet_factory_(rpc_url_, address);
    }
    return std::make_unique<QuipWallet>(rpc_url_, address);
  }

  std::string rpc_url_;
  std::string contract_address_;
  std::unique_ptr<QuipFactory> factory_;
  std::function<std::unique_ptr<QuipWallet>(const std::string &,
                                            const std::string &)>
      wallet_factory_;
};

} // namespace quip