#include "cli.hpp"
#include <iostream>
#include <map>
#include <string>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0]
              << " [--rpc-url <url>] [--contract-address <address>] <command> "
                 "[args...]"
              << std::endl;
    std::cerr << "Default RPC URL: http://localhost:8545" << std::endl;
    return 1;
  }

  // Default values
  std::string rpc_url = "http://localhost:8545";
  std::string contract_address = "";
  std::vector<std::string> command_args;

  // Parse command line arguments
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "--rpc-url" && i + 1 < argc) {
      rpc_url = argv[++i];
    } else if (arg == "--contract-address" && i + 1 < argc) {
      contract_address = argv[++i];
    } else if (arg.substr(0, 2) == "--") {
      std::cerr << "Unknown option: " << arg << std::endl;
      return 1;
    } else {
      // Everything else is part of the command
      for (int j = i; j < argc; ++j) {
        command_args.push_back(argv[j]);
      }
      break;
    }
  }

  if (command_args.empty()) {
    std::cerr << "No command specified" << std::endl;
    return 1;
  }

  try {
    quip::CLI cli(rpc_url, contract_address);
    return cli.execute(command_args) ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}