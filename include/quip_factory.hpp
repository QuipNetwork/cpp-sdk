#pragma once

#include "common.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace quip {

struct Vault {
  VaultId id;
  Address classical_address;
  WinternitzAddress pq_address;
};

class QuipFactory {
public:
  QuipFactory(const std::string &rpc_url,
              const std::string &contract_address = "");
  ~QuipFactory();

  // Correct depositToWinternitz signature matching the Solidity contract
  Address depositToWinternitz(const VaultId &vaultId, const Address &to,
                              const WinternitzAddress &pqTo,
                              const PrivateKey &private_key,
                              const Amount &amount = 0);

  Address getQuipWalletAddress(const VaultId &vaultId, const Address &to);
  virtual Amount getCreationFee();
  virtual Amount getTransferFee();
  virtual Amount getExecuteFee();

  std::vector<Vault> getVaults(const Address &owner);

  // Get the wallet's balance

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace quip