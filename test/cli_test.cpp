#include "cli.hpp"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace quip;

class CLITest : public ::testing::Test {
protected:
  void SetUp() override {
    cli_ = std::make_unique<CLI>("http://localhost:8545");
  }

  std::unique_ptr<CLI> cli_;
};

TEST_F(CLITest, InvalidCommand) {
  std::vector<std::string> args = {"invalid"};
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, DepositCommand) {
  std::vector<std::string> args = {
      "deposit",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "1000000000000000000"};
  // TODO: Mock the QuipFactory and verify the deposit call
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, TransferCommand) {
  std::vector<std::string> args = {
      "transfer",
      "0x1234567890123456789012345678901234567890",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890",
      "1000000000000000000",
      "0x1234567890123456789012345678901234567890123456789012345678901234"};
  // TODO: Mock the QuipWallet and verify the transfer call
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, ExecuteCommand) {
  std::vector<std::string> args = {
      "execute",
      "0x1234567890123456789012345678901234567890",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890",
      "0x12345678",
      "0x1234567890123456789012345678901234567890123456789012345678901234"};
  // TODO: Mock the QuipWallet and verify the execute call
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, ChangeOwnerCommand) {
  std::vector<std::string> args = {
      "change-owner", "0x1234567890123456789012345678901234567890",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890123456789012345678901234",
      "0x1234567890123456789012345678901234567890123456789012345678901234"};
  // TODO: Mock the QuipWallet and verify the change owner call
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, BalanceCommand) {
  std::vector<std::string> args = {
      "balance", "0x1234567890123456789012345678901234567890"};
  // TODO: Mock the QuipWallet and verify the balance call
  EXPECT_FALSE(cli_->execute(args));
}

TEST_F(CLITest, PQOwnerCommand) {
  std::vector<std::string> args = {
      "pq-owner", "0x1234567890123456789012345678901234567890"};
  // TODO: Mock the QuipWallet and verify the PQ owner call
  EXPECT_FALSE(cli_->execute(args));
}