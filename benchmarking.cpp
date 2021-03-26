//
// Created by jelle on 14-10-20.
//

#include "benchmarking.h"
#include "threshold_paillier.h"
#include "psi_protocols.h"


double sample_mean(const std::vector<long>& measurements) {
    // Computes the sample mean
    double sum = 0;

    for (long measurement : measurements) {
        sum += measurement;
    }

    return sum / measurements.size();
}


double sample_std(const std::vector<long>& measurements, double mean) {
    // Computes the corrected sample standard deviation
    double sum = 0;

    for (long measurement : measurements) {
        sum += pow(measurement - mean, 2);
    }

    return sqrt(sum / (measurements.size() - 1.0));
}


void benchmark(std::vector<long> parties_t, std::vector<long> set_size_exponents) {
    // Pre-generate all keys
    std::vector<std::pair<Keys, Keys>> keys;
    keys.reserve(parties_t.size());
    for (long t : parties_t) {
        Keys k_1;
        key_gen(&k_1, 1024, t/2, t);

        Keys k_tm1;
        key_gen(&k_tm1, 1024, t-1, t);

        keys.emplace_back(k_1, k_tm1);
    }
    // -> Normally, the keys would be distributed to the parties now

    // Run the experiments
    for (int t_i = 0; t_i < parties_t.size(); ++t_i) {
        std::cout << "time_" << parties_t.at(t_i) << "_parties = process([";

        for (long exp : set_size_exponents) {
            // Generate sets for each experiment
            std::vector<std::vector<std::vector<long>>> experiment_sets;
            for (int i = 0; i < 10; ++i) {
                std::vector<std::vector<long>> client_sets;
                // Generate a set for each client
                for (int j = 0; j < parties_t.at(t_i); ++j) {
                    std::vector<long> set;
                    set.reserve(1 << exp);
                    for (unsigned long k = 0; k < (1 << exp); ++k) {
                        // TODO: User random long instead of int
                        set.push_back(rand());
                    }
                    client_sets.push_back(set);
                }
                experiment_sets.push_back(client_sets);
            }

            // Use epsilon = 2^-7, which gives less than 1% false positive rate
            long m_bits = ceil((7.0 * (1 << exp)) / log(2.0));
            long k_hashes = 7;

            // Run each experiment 10 times
            std::vector<double> means_t2;
            std::vector<double> std_t2;
            std::vector<double> means_tm1;
            std::vector<double> std_tm1;

            // threshold l = t / 2
            std::vector<long> times;

            for (int i = 0; i < 10; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                multiparty_psi(experiment_sets.at(i), parties_t.at(t_i) / 2, m_bits, k_hashes, keys.at(t_i).first);
                auto stop = std::chrono::high_resolution_clock::now();

                times.push_back((stop-start).count());
            }

            double mean = sample_mean(times);
            double std = sample_std(times, mean);
            std::cout << "[(" << mean << ", " << std << "), ";

            // threshold l = t - 1

            for (int i = 0; i < 10; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                multiparty_psi(experiment_sets.at(i), parties_t.at(t_i) - 1, m_bits, k_hashes, keys.at(t_i).second);
                auto stop = std::chrono::high_resolution_clock::now();

                times.push_back((stop-start).count());
            }

            mean = sample_mean(times);
            std = sample_std(times, mean);
            std::cout << "(" << mean << ", " << std << ")], ";
        }

        std::cout << "])" << std::endl;
    }
}


void threshold_benchmark(std::vector<long> parties_t, std::vector<long> set_size_exponents) {
    // Pre-generate all keys
    std::vector<std::pair<Keys, Keys>> keys;
    keys.reserve(parties_t.size());
    for (long t : parties_t) {
        Keys k_1;
        key_gen(&k_1, 1024, t/2, t);

        Keys k_tm1;
        key_gen(&k_tm1, 1024, t-1, t);

        keys.emplace_back(k_1, k_tm1);
    }
    // -> Normally, the keys would be distributed to the parties now

    // Run the experiments
    for (int t_i = 0; t_i < parties_t.size(); ++t_i) {
        std::cout << "time_" << parties_t.at(t_i) << "_parties = process([";

        for (long exp : set_size_exponents) {
            // Generate sets for each experiment
            std::vector<std::vector<std::vector<long>>> experiment_sets;
            for (int i = 0; i < 10; ++i) {
                std::vector<std::vector<long>> client_sets;
                // Generate a set for each client
                for (int j = 0; j < parties_t.at(t_i); ++j) {
                    std::vector<long> set;
                    set.reserve(1 << exp);
                    for (unsigned long k = 0; k < (1 << exp); ++k) {
                        // TODO: User random long instead of int
                        set.push_back(rand());
                    }
                    client_sets.push_back(set);
                }
                experiment_sets.push_back(client_sets);
            }

            // Use epsilon = 2^-7, which gives less than 1% false positive rate
            long m_bits = ceil((7.0 * (1 << exp)) / log(2.0));
            long k_hashes = 7;

            // Run each experiment 10 times
            std::vector<double> means_t2;
            std::vector<double> std_t2;
            std::vector<double> means_tm1;
            std::vector<double> std_tm1;

            // threshold l = t / 2
            std::vector<long> times;

            for (int i = 0; i < 10; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                threshold_multiparty_psi(experiment_sets.at(i), parties_t.at(t_i) / 2, m_bits, k_hashes,
                                         experiment_sets.at(0).size() / 2, keys.at(t_i).first);
                auto stop = std::chrono::high_resolution_clock::now();

                times.push_back((stop-start).count());
            }

            double mean = sample_mean(times);
            double std = sample_std(times, mean);
            std::cout << "[(" << mean << ", " << std << "), ";

            // threshold l = t - 1

            for (int i = 0; i < 10; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                threshold_multiparty_psi(experiment_sets.at(i), parties_t.at(t_i) - 1, m_bits, k_hashes,
                                         experiment_sets.at(0).size() / 2, keys.at(t_i).second);
                auto stop = std::chrono::high_resolution_clock::now();

                times.push_back((stop-start).count());
            }

            mean = sample_mean(times);
            std = sample_std(times, mean);
            std::cout << "(" << mean << ", " << std << ")], ";
        }

        std::cout << "])" << std::endl;
    }
}
