cmake_minimum_required(VERSION 3.17)
project(multiparty_psi_fresh)

# Set global variables
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pthread")

# Load dependencies
find_package(GMP REQUIRED)
find_package(NTL REQUIRED)

# Libraries
add_library(MurmurHash3 MurmurHash3.h MurmurHash3.cpp)
add_library(ThresholdPaillier threshold_paillier.h threshold_paillier.cpp)
add_library(BloomFilter bloom_filter.h bloom_filter.cpp)
add_library(PSIProtocols psi_protocols.h psi_protocols.cpp)
add_library(SubProtocols sub_protocols.h sub_protocols.cpp)

# Bundle everything together
add_executable(multiparty_psi_fresh main.cpp)
target_include_directories(multiparty_psi_fresh PUBLIC ${NTL_INCLUDE_DIR} ${GMP_INCLUDE_DIR})
target_link_libraries(multiparty_psi_fresh
        PSIProtocols
        BloomFilter
        MurmurHash3
        ThresholdPaillier
        ${NTL_LIBRARY}
        ${GMP_LIBRARIES})
