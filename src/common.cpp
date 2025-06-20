#include "../include/common.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace quip {

// Shared ABI encoding function implementation
std::string abiEncode(const std::string &function_name,
                      const std::string &abi_json,
                      const std::string &params_json) {
  // Escape quotes in the JSON strings for shell command
  std::string escaped_abi = abi_json;
  std::string escaped_params = params_json;

  // Replace " with \" for shell safety
  size_t pos = 0;
  while ((pos = escaped_abi.find("\"", pos)) != std::string::npos) {
    escaped_abi.replace(pos, 1, "\\\"");
    pos += 2;
  }
  pos = 0;
  while ((pos = escaped_params.find("\"", pos)) != std::string::npos) {
    escaped_params.replace(pos, 1, "\\\"");
    pos += 2;
  }

  std::string command =
      "cd ./ethereum-sdk/scripts && npx ts-node abiEncode.ts \"" + escaped_abi +
      "\" \"" + function_name + "\" \"" + escaped_params + "\"";

  FILE *pipe = popen(command.c_str(), "r");
  if (!pipe) {
    throw std::runtime_error("Failed to execute ABI encoding script");
  }

  std::string result;
  char buffer[128];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }

  int status = pclose(pipe);
  if (status != 0) {
    // Debug output
    std::cerr << "Debug: Executing command: " << command << std::endl;
    throw std::runtime_error("ABI encoding script failed with status " +
                             std::to_string(status));
  }

  // Remove trailing newline
  if (!result.empty() && result.back() == '\n') {
    result.pop_back();
  }

  // Debug output
  std::cerr << "Debug: ABI encoding result: " << result << std::endl;

  return result;
}

} // namespace quip