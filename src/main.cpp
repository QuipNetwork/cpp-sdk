#include "cli.hpp"
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <rpc_url> [command] [args...]"
              << std::endl;
    return 1;
  }

  std::string rpc_url = argv[1];
  std::vector<std::string> args;
  for (int i = 2; i < argc; ++i) {
    args.push_back(argv[i]);
  }

  try {
    quip::CLI cli(rpc_url);
    return cli.execute(args) ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}