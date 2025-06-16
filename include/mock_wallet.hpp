#pragma once

#include "common.hpp"
#include "quip_wallet.hpp"
#include <functional>
#include <memory>
#include <string>

namespace quip {

class MockQuipWallet : public QuipWallet {
public:
  MockQuipWallet(const std::string &rpc_url,
                 const std::string &contract_address)
      : QuipWallet(rpc_url, contract_address) {}

  // Mock function handlers
  std::function<bool(const PublicKey &, const Signature &, const Address &,
                     Amount, const PrivateKey &)>
      transferWithWinternitzMock;
  std::function<bool(const PublicKey &, const Signature &, const Address &,
                     const std::vector<uint8_t> &, const PrivateKey &)>
      executeWithWinternitzMock;
  std::function<bool(const PublicKey &, const Signature &, const PrivateKey &)>
      changePqOwnerMock;
  std::function<Address()> getPqOwnerMock;
  std::function<Amount()> getBalanceMock;

  // Override virtual functions
  bool transferWithWinternitz(const PublicKey &pq_pubkey,
                              const Signature &pq_sig,
                              const Address &to_address, Amount amount,
                              const PrivateKey &private_key) override {
    if (transferWithWinternitzMock) {
      return transferWithWinternitzMock(pq_pubkey, pq_sig, to_address, amount,
                                        private_key);
    }
    return QuipWallet::transferWithWinternitz(pq_pubkey, pq_sig, to_address,
                                              amount, private_key);
  }

  bool executeWithWinternitz(const PublicKey &pq_pubkey,
                             const Signature &pq_sig,
                             const Address &target_address,
                             const std::vector<uint8_t> &opdata,
                             const PrivateKey &private_key) override {
    if (executeWithWinternitzMock) {
      return executeWithWinternitzMock(pq_pubkey, pq_sig, target_address,
                                       opdata, private_key);
    }
    return QuipWallet::executeWithWinternitz(pq_pubkey, pq_sig, target_address,
                                             opdata, private_key);
  }

  bool changePqOwner(const PublicKey &pq_pubkey, const Signature &pq_sig,
                     const PrivateKey &private_key) override {
    if (changePqOwnerMock) {
      return changePqOwnerMock(pq_pubkey, pq_sig, private_key);
    }
    return QuipWallet::changePqOwner(pq_pubkey, pq_sig, private_key);
  }

  Address getPqOwner() override {
    if (getPqOwnerMock) {
      return getPqOwnerMock();
    }
    return QuipWallet::getPqOwner();
  }

  Amount getBalance() override {
    if (getBalanceMock) {
      return getBalanceMock();
    }
    return QuipWallet::getBalance();
  }
};

} // namespace quip