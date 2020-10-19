//
// Created by jelle on 14-10-20.
//

#include "benchmarking.h"
#include "threshold_paillier.h"
#include "psi_protocols.h"


void benchmark(std::vector<long> parties_t, std::vector<long> set_size_exponents) {
    // Pre-generate all keys
    std::vector<std::pair<Keys, Keys>> keys;
    keys.reserve(parties_t.size());
    for (long t : parties_t) {
        Keys k_1;
        key_gen(&k_1, 1024, 1, t);

        Keys k_tm1;
        key_gen(&k_tm1, 1024, t-1, t);

        keys.emplace_back(k_1, k_tm1);
    }
    // -> Normally, the keys would be distributed to the parties now

    // Run the experiments
    for (long t : parties_t) {
        for (long exp : set_size_exponents) {
            // Generate sets for each experiment
            std::vector<std::vector<std::vector<long>>> experiment_sets;
            for (int i = 0; i < 10; ++i) {
                std::vector<std::vector<long>> client_sets;
                // Generate a set for each client
                for (int j = 0; j < t; ++j) {
                    std::vector<long> set;
                    // TODO: Check if this range works
                    set.reserve(1 << exp);
                    for (unsigned long k = 0; k < (1 << exp); ++k) {
                        // TODO: User random long instead of int
                        set.push_back(rand());
                    }
                    client_sets.push_back(set);
                }
                experiment_sets.push_back(client_sets);
            }

            auto start = std::chrono::high_resolution_clock::now();

            // Run each experiment 10 times
            for (int i = 0; i < 10; ++i) {
                // TODO: Precompute m and k
                std::cout << "start" << std::endl;
                multiparty_psi(experiment_sets.at(i), 1, 16, 4, keys.at(t).first);
                std::cout << "stop" << std::endl;
            }

            auto stop = std::chrono::high_resolution_clock::now();

            std::cout << (stop-start).count() << std::endl;
        }
    }
}
