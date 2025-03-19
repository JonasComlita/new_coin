cmake_minimum_required(VERSION 3.10)
project(blockchain_extensions)

# Find required packages
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${Python3_INCLUDE_DIRS}
    ${pybind11_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Create blockchain_cpp module
add_library(blockchain_cpp MODULE 
    "${CMAKE_SOURCE_DIR}/cpp_extensions/blockchain_cpp.cpp"
)

# Link libraries
target_link_libraries(blockchain_cpp 
    PRIVATE 
    pybind11::module 
    ${OPENSSL_LIBRARIES}
)

# Set output properties
set_target_properties(blockchain_cpp PROPERTIES
    PREFIX ""
    SUFFIX ".pyd"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)