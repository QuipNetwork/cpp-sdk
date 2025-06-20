#pragma once

#include "common.hpp"

namespace quip {

class QuipWallet {
public:
  QuipWallet(const string &rpc_url, const string &contract_address);
  virtual ~QuipWallet();

  // Transfer funds using Winternitz signature
  virtual bool
  transferWithWinternitz(const WinternitzAddress &winternitz_address,
                         const Signature &pq_sig, const Address &to_address,
                         Amount amount);

  // Execute a contract call using Winternitz signature
  virtual bool
  executeWithWinternitz(const WinternitzAddress &winternitz_address,
                        const Signature &pq_sig, const Address &target_address,
                        const vector<uint8_t> &opdata);

  // Change the PQ owner using Winternitz signature
  virtual bool changePqOwner(const WinternitzAddress &winternitz_address,
                             const Signature &pq_sig);

  // Get the current PQ owner
  virtual Address getPqOwner();

  // Get the wallet's balance
  virtual Amount getBalance();

private:
  class Impl;
  unique_ptr<Impl> impl_;
};

} // namespace quip