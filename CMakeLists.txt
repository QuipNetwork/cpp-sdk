cmake_minimum_required(VERSION 3.10)
project(quip-cli)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include FetchContent
include(FetchContent)

# Fetch nlohmann_json
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# Set hashsigs library path
set(HASHSIGS_ROOT "${CMAKE_SOURCE_DIR}/../hashsigs-cpp")
set(HASHSIGS_LIBRARY_PATH "${HASHSIGS_ROOT}/build/lib/libhashsigs.a")

if(NOT EXISTS "${HASHSIGS_LIBRARY_PATH}")
    message(FATAL_ERROR "hashsigs library not found at ${HASHSIGS_LIBRARY_PATH}. Please build hashsigs-cpp first.")
endif()

# Find required packages
find_package(CURL REQUIRED)
find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

# Common source files
set(QUIP_CLI_SOURCES
    src/main.cpp
    src/cli.cpp
    src/common.cpp
    src/quip_factory.cpp
    src/quip_wallet.cpp
)

# Main executable
add_executable(quip-cli ${QUIP_CLI_SOURCES})

target_include_directories(quip-cli
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${HASHSIGS_ROOT}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}/_deps/json-src/include
)

target_link_libraries(quip-cli
    PRIVATE
    ${HASHSIGS_LIBRARY_PATH}
    CURL::libcurl
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Test executable
enable_testing()
add_executable(quip-cli-tests
    test/cli_test.cpp
    test/quip_factory_test.cpp
    test/quip_wallet_test.cpp
    src/cli.cpp
    src/common.cpp
    src/quip_factory.cpp
    src/quip_wallet.cpp
)

target_include_directories(quip-cli-tests
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${HASHSIGS_ROOT}/include
    ${CMAKE_SOURCE_DIR}/test
    ${GTEST_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}/_deps/json-src/include
)

target_link_libraries(quip-cli-tests
    PRIVATE
    ${HASHSIGS_LIBRARY_PATH}
    CURL::libcurl
    nlohmann_json::nlohmann_json
    GTest::GTest
    GTest::Main
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_test(NAME quip-cli-tests COMMAND quip-cli-tests) 