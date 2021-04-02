//
// Created by Jelle Vos on 02-04-21.
//
#include <iostream>
#include <vector>
#include "psi_protocols.h"
#include "benchmarking.h"


int main() {
    Keys keys;
    key_gen(&keys, 1024, 2, 3);

    std::vector<long> client1_set({1, 3, 5, 7});
    std::vector<long> client2_set({2, 3, 4, 5});
    std::vector<long> server_set({6, 5, 2, 1});

    std::cout << "Computing the set intersection between multiple parties using a (2, 3)-encryption of 1024 bits."
              << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<long> result = multiparty_psi(std::vector({client1_set, client2_set}), server_set,
                                              2,
                                              16, 4,
                                              keys);
    auto stop = std::chrono::high_resolution_clock::now();

    std::cout << "The resulting set intersection was: { ";
    for (long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl;
    std::cout << "Took: " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count() << " ms."
        << std::endl << std::endl;


    std::cout << "Computing the threshold set intersection between multiple parties using a (2, 3)-encryption of 1024 bits."
              << std::endl;

    start = std::chrono::high_resolution_clock::now();
    result = threshold_multiparty_psi(std::vector({client1_set, client2_set}), server_set,
                                                            2,
                                                            16, 4,
                                                            1,
                                                            keys);
    stop = std::chrono::high_resolution_clock::now();


    std::cout << "The resulting threshold set intersection was: { ";
    for (long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl << std::endl;
    std::cout << "Took: " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count() << " ms."
              << std::endl << std::endl;

    std::cout << "Run benchmarks for MPSI (y/n): ";

    if (std::cin.get() == 'y') {
        std::cout << "Running benchmarks (without simulated delays) using a 1024-bit key:" << std::endl;
        benchmark(std::vector<long>({5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100}), std::vector<long>({4, 6, 7}));
    }

    std::cin.ignore( std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Run benchmarks for T-MPSI (y/n): ";

    if (std::cin.get() == 'y') {
        std::cout << "Running benchmarks (without simulated delays) using a 1024-bit key:" << std::endl;
        //threshold_benchmark(std::vector<long>({5, 10, 20, 30, 40, 50}), std::vector<long>({2, 4, 5}));
        threshold_benchmark(std::vector<long>({50, 40, 30, 20, 10, 5}), std::vector<long>({2, 4, 5}));
    }

    return 0;
}
