#!/bin/bash

# Exit on error
set -e

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "CMake is required but not installed. Aborting." >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required but not installed. Aborting." >&2; exit 1; }

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Check if Homebrew is installed
    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew is required but not installed. Please install it from https://brew.sh"
        exit 1
    fi

    # Install required dependencies
    echo "Installing required dependencies..."
    brew install cmake curl googletest openssl
fi

# Store the current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Build hashsigs-cpp first
echo "Building hashsigs-cpp..."
cd "${SCRIPT_DIR}/../hashsigs-cpp"
rm -rf build
mkdir -p build
cd build
cmake ..
cmake --build .
cd "${SCRIPT_DIR}"

# Clean and recreate build directory
echo "Building quip-cli..."
rm -rf build
mkdir -p build
cd build

# Configure with CMake
cmake "${SCRIPT_DIR}"

# Build
cmake --build .

# Run tests
ctest --output-on-failure

echo "Build completed successfully!" 