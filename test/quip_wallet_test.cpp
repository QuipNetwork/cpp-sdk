#include "../include/quip_wallet.hpp"
#include <array>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>
#include <wotsplus.hpp>

using namespace quip;
using namespace hashsigs;

class QuipWalletTest : public ::testing::Test {
protected:
  void SetUp() override {
    // TODO: Set up test environment with mock RPC server
    wallet_ = std::make_unique<QuipWallet>("http://localhost:8545", "0x1234");
  }

  std::unique_ptr<QuipWallet> wallet_;
};

TEST_F(QuipWalletTest, TransferWithWinternitz) {
  // Create test public key
  hashsigs::WOTSPlus wots([](const std::vector<uint8_t> &data) {
    return std::array<uint8_t, 32>{};
  });

  auto keypair = wots.generate_key_pair(std::array<uint8_t, 32>{});

  std::string to_address = "0x1234567890123456789012345678901234567890";
  std::string private_key =
      "0x1234567890123456789012345678901234567890123456789012345678901234";

  // Create test signature
  std::vector<std::array<uint8_t, 32>> pq_sig;
  for (int i = 0; i < 67; ++i) { // 67 is the number of signature elements
    pq_sig.push_back(std::array<uint8_t, 32>{});
  }

  // Test transfer
  EXPECT_NO_THROW({
    bool success = wallet_->transferWithWinternitz(
        keypair.first.get_public_seed(), pq_sig, to_address,
        1000000000000000000, // 1 ETH
        private_key);
    EXPECT_TRUE(success);
  });
}

TEST_F(QuipWalletTest, ExecuteWithWinternitz) {
  // Create test public key
  hashsigs::WOTSPlus wots([](const std::vector<uint8_t> &data) {
    return std::array<uint8_t, 32>{};
  });

  auto keypair = wots.generate_key_pair(std::array<uint8_t, 32>{});

  std::string target_address = "0x1234567890123456789012345678901234567890";
  std::string private_key =
      "0x1234567890123456789012345678901234567890123456789012345678901234";

  // Create test signature
  std::vector<std::array<uint8_t, 32>> pq_sig;
  for (int i = 0; i < 67; ++i) {
    pq_sig.push_back(std::array<uint8_t, 32>{});
  }

  // Create test opdata
  std::vector<uint8_t> opdata = {0x12, 0x34, 0x56, 0x78};

  // Test execute
  EXPECT_NO_THROW({
    bool success =
        wallet_->executeWithWinternitz(keypair.first.get_public_seed(), pq_sig,
                                       target_address, opdata, private_key);
    EXPECT_TRUE(success);
  });
}

TEST_F(QuipWalletTest, ChangePqOwner) {
  // Create test public key
  hashsigs::WOTSPlus wots([](const std::vector<uint8_t> &data) {
    return std::array<uint8_t, 32>{};
  });

  auto keypair = wots.generate_key_pair(std::array<uint8_t, 32>{});

  std::string private_key =
      "0x1234567890123456789012345678901234567890123456789012345678901234";

  // Create test signature
  std::vector<std::array<uint8_t, 32>> pq_sig;
  for (int i = 0; i < 67; ++i) {
    pq_sig.push_back(std::array<uint8_t, 32>{});
  }

  // Test change owner
  EXPECT_NO_THROW({
    bool success = wallet_->changePqOwner(keypair.first.get_public_seed(),
                                          pq_sig, private_key);
    EXPECT_TRUE(success);
  });
}

TEST_F(QuipWalletTest, GetPqOwner) {
  // Test getting PQ owner
  EXPECT_NO_THROW({
    auto pq_owner = wallet_->getPqOwner();
    // TODO: Add more specific assertions about the PQ owner
  });
}

TEST_F(QuipWalletTest, GetBalance) {
  // Test getting balance
  EXPECT_NO_THROW({
    auto balance = wallet_->getBalance();
    EXPECT_GE(balance, 0);
  });
}