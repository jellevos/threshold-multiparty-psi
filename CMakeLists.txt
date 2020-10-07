cmake_minimum_required(VERSION 3.17)
project(multiparty_psi_fresh)

set(CMAKE_CXX_STANDARD 20)

add_executable(multiparty_psi_fresh main.cpp MurmurHash3.cpp MurmurHash3.h threshold_paillier.cpp threshold_paillier.hpp)
