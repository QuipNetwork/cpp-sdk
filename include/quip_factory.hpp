#pragma once

#include "common.hpp"

namespace quip {

class QuipFactory {
public:
  QuipFactory(const string &rpc_url, const string &contract_address);
  ~QuipFactory();

  bool depositToWinternitz(const PublicKey &pq_pubkey, const Signature &pq_sig,
                           const PrivateKey &private_key);

  Address getQuipWalletAddress(const PublicKey &pq_pubkey);
  Amount getCreationFee();
  Amount getTransferFee();
  Amount getExecuteFee();

private:
  class Impl;
  unique_ptr<Impl> impl_;
};

} // namespace quip