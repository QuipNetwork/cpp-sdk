#pragma once

#include "common.hpp"

namespace quip {

class QuipFactory {
public:
  QuipFactory(const string &rpc_url, const string &contract_address);
  ~QuipFactory();

  // Correct depositToWinternitz signature matching the Solidity contract
  Address depositToWinternitz(const VaultId &vaultId, const Address &to,
                              const WinternitzAddress &pqTo,
                              const PrivateKey &private_key,
                              const Amount &amount = 0);

  Address getQuipWalletAddress(const VaultId &vaultId, const Address &to);
  Amount getCreationFee();
  Amount getTransferFee();
  Amount getExecuteFee();

private:
  class Impl;
  unique_ptr<Impl> impl_;
};

} // namespace quip