cmake_minimum_required(VERSION 3.25)
project(netlearn CXX)

# Set C++ standard to C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD  17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include Conan toolchain if it exists
if(EXISTS "${CMAKE_BINARY_DIR}/conan_toolchain.cmake")
    include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
endif()

# Find packages
find_package(CLI11 REQUIRED)
find_package(libpcap REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)
find_package(benchmark REQUIRED)

# Enable testing
enable_testing()

# Add main application
add_executable(netlearn
    src/main.cpp
)
target_link_libraries(netlearn 
    PRIVATE
    CLI11::CLI11
    libpcap::libpcap
    spdlog::spdlog
)
target_include_directories(netlearn PRIVATE src)

# Add tests
add_executable(netlearn_tests
    tests/test_logger.cpp
    tests/test_utils.cpp
)
target_link_libraries(netlearn_tests
    PRIVATE
    GTest::gtest_main
    GTest::gtest
    spdlog::spdlog
)
target_include_directories(netlearn_tests PRIVATE src)
add_test(NAME netrlearn_tests COMMAND netlearn_tests)

# Add benchmarks
add_executable(netlearn_benchmark
    benchmarks/bench_logger.cpp
)
target_link_libraries(netlearn_benchmark
    PRIVATE
    benchmark::benchmark
    spdlog::spdlog
)
target_include_directories(netlearn_benchmark PRIVATE src)

# Set output directories
set_target_properties(netlearn PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(netlearn_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)
set_target_properties(netlearn_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/benchmarks"
)
