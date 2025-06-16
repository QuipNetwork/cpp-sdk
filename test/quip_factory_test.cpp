#include "quip_factory.hpp"
#include <array>
#include <gtest/gtest.h>
#include <string>

using namespace quip;

class QuipFactoryTest : public ::testing::Test {
protected:
  void SetUp() override {
    // TODO: Set up test environment with mock RPC server
    factory_ = std::make_unique<QuipFactory>("http://localhost:8545", "0x1234");
  }

  std::unique_ptr<QuipFactory> factory_;
};

TEST_F(QuipFactoryTest, DepositToWinternitz) {
  // Create a test public key (32 bytes)
  PublicKey pq_pubkey = {};
  pq_pubkey.fill(0x01);

  // Create a test signature (vector of 32-byte arrays)
  Signature pq_sig(1);
  pq_sig[0].fill(0x02);

  PrivateKey private_key =
      "0x1234567890123456789012345678901234567890123456789012345678901234";

  // Test deposit
  EXPECT_NO_THROW({
    bool result = factory_->depositToWinternitz(pq_pubkey, pq_sig, private_key);
    EXPECT_TRUE(result);
  });
}

TEST_F(QuipFactoryTest, GetQuipWalletAddress) {
  // Create a test public key (32 bytes)
  PublicKey pq_pubkey = {};
  pq_pubkey.fill(0x01);

  // Test getting wallet address
  EXPECT_NO_THROW({
    Address wallet_address = factory_->getQuipWalletAddress(pq_pubkey);
    EXPECT_FALSE(wallet_address.empty());
  });
}

TEST_F(QuipFactoryTest, GetFees) {
  // Test getting fees
  EXPECT_NO_THROW({
    auto creation_fee = factory_->getCreationFee();
    auto transfer_fee = factory_->getTransferFee();
    auto execute_fee = factory_->getExecuteFee();

    EXPECT_GE(creation_fee, 0);
    EXPECT_GE(transfer_fee, 0);
    EXPECT_GE(execute_fee, 0);
  });
}