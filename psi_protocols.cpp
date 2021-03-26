//
// Created by jelle on 09-10-20.
//
#include <thread>
#include <future>
#include "psi_protocols.h"

template <class T>
void await_futures(std::vector<std::future<T>> &futures) {
    bool processing = true;
    while (processing) {
        processing = false;

        for (auto &future : futures) {
            if (not future.valid()) {
                processing = true;
                break;
            }
        }
    }
}

std::vector<long> multiparty_psi(std::vector<std::vector<long>> sets,
                                 long threshold_l,
                                 long m_bits, long k_hashes,
                                 Keys &keys) {
    std::vector<std::vector<long>> client_sets;
    client_sets.reserve(sets.size() - 1);
    for (int i = 0; i < sets.size() - 1; ++i) {
        client_sets.push_back(sets.at(i));
    }

    std::vector<long> server_set = sets.at(sets.size() - 1);

    return multiparty_psi(client_sets, server_set, threshold_l, m_bits, k_hashes, keys);
}

std::vector<ZZ> generate_eibf(std::vector<long> &client_set, long m_bits, long k_hashes, Keys &keys) {
    BloomFilter bloom_filter(m_bits, k_hashes);

    // Step 1
    for (long element : client_set) {
        bloom_filter.insert(element);
    }

    // Step 2
    bloom_filter.invert();

    // Step 3
    std::vector<ZZ> eibf;
    bloom_filter.encrypt_all(eibf, keys.public_key);

    return eibf;
}

std::vector<ZZ> randomize_ciphertexts(std::vector<ZZ> ciphertexts, Keys &keys) {
    std::vector<ZZ> randomized_ciphertexts;
    randomized_ciphertexts.reserve(ciphertexts.size());

    for (const ZZ& ciphertext : ciphertexts) {
        ZZ random = Gen_Coprime(keys.public_key.n);
        randomized_ciphertexts.push_back(multiply_homomorphically(ciphertext, random, keys.public_key));
    }

    return randomized_ciphertexts;
}

std::vector<std::pair<long, ZZ>> compute_decryption_shares(std::vector<ZZ> ciphertexts, long client_id, Keys &keys) {
    std::vector<std::pair<long, ZZ>> decryption_shares;
    decryption_shares.reserve(ciphertexts.size());

    for (auto ciphertext : ciphertexts) {
        decryption_shares.emplace_back(client_id + 1, partial_decrypt(ciphertext, keys.public_key,
                                                              keys.private_keys.at(client_id)));
    }

    return decryption_shares;
}

// TODO: Clean up
// TODO: Fix all file headers
std::vector<long> multiparty_psi(std::vector<std::vector<long>> client_sets,
                                 std::vector<long> server_set,
                                 long threshold_l,
                                 long m_bits, long k_hashes,
                                 Keys &keys) {
    //// MPSI protocol

    /// Initialization
    // TODO: Send?


    /// Local EIBF generation

    // 1-3. Clients compute their Bloom filter, invert it and encrypt it (generating EIBFs)
    std::vector<std::future<std::vector<ZZ>>> eibf_futures;
    eibf_futures.reserve(client_sets.size());
    for (auto & client_set : client_sets) {
        eibf_futures.push_back(std::async(std::launch::async, generate_eibf, std::ref(client_set), m_bits, k_hashes, std::ref(keys)));
    }

    // Wait till the processing is done
    await_futures(eibf_futures);

    // Extract the generated EIBFs from the clients
    std::vector<std::vector<ZZ>> client_eibfs;
    client_eibfs.reserve(client_sets.size());
    for (std::future<std::vector<ZZ>> &future : eibf_futures) {
        client_eibfs.push_back(future.get());
    }

    // 4. Send the encrypted Bloom filters to the server
    // TODO: Implement sending


    /// Set Intersection Computation
    // 1-2. Use the k hashes to select elements from the EIBFs and sum them up homomorphically,
    //      rerandomize afterwards.
    std::vector<ZZ> ciphertexts;
    ciphertexts.reserve(server_set.size());
    for (long element : server_set) {
        // Compute for the first hash function
        unsigned long index = BloomFilter::hash(element, 0) % m_bits;
        ZZ ciphertext = client_eibfs.at(0).at(index);
        for (int i = 1; i < client_eibfs.size(); ++i) {
            // From client i add the bit at index from their EIBF
            ciphertext = add_homomorphically(ciphertext, client_eibfs.at(i).at(index), keys.public_key);
        }

        // Compute for the remaining hash functions
        for (int i = 1; i < k_hashes; ++i) {
            index = BloomFilter::hash(element, i) % m_bits;

            // Sum up all selected ciphertexts
            for (std::vector<ZZ> eibf : client_eibfs) {
                ciphertext = add_homomorphically(ciphertext, eibf.at(index), keys.public_key);
            }
        }

        // Rerandomize the ciphertext to prevent analysis due to the deterministic nature of homomorphic addition
        ciphertext = rerandomize(ciphertext, keys.public_key);

        ciphertexts.push_back(ciphertext);
    }

    // 3. The ciphertexts get sent to l parties
    // TODO: Send to clients (look into threshold)

    // 4. Decrypt-to-zero each ciphertext in collaboration with the clients
    std::vector<std::future<std::vector<ZZ>>> randomization_futures;
    randomization_futures.reserve(client_sets.size());
    for (int i = 0; i < client_sets.size(); ++i) {
        randomization_futures.push_back(std::async(std::launch::async, randomize_ciphertexts, ciphertexts, std::ref(keys)));
    }

    // Wait till the processing is done
    await_futures(randomization_futures);

    // Extract the randomized ciphertexts from the clients
    std::vector<std::vector<ZZ>> client_ciphertexts;
    client_ciphertexts.reserve(client_sets.size());
    for (std::future<std::vector<ZZ>> &future : randomization_futures) {
        client_ciphertexts.push_back(future.get());
    }

    // Sum up all clients' randomized ciphertexts
    std::vector<ZZ> randomized_ciphertexts = client_ciphertexts.at(0);
    for (int i = 1; i < client_ciphertexts.size(); ++i) {
        for (int j = 0; j < ciphertexts.size(); ++j) {
            randomized_ciphertexts.at(j) = add_homomorphically(randomized_ciphertexts.at(j), client_ciphertexts.at(i).at(j), keys.public_key);
        }
    }

    // Partial decryption (let threshold + 1 parties decrypt)
    std::vector<std::future<std::vector<std::pair<long, ZZ>>>> decryption_share_futures;
    decryption_share_futures.reserve(threshold_l + 1);
    for (int i = 0; i < (threshold_l + 1); ++i) {
        decryption_share_futures.push_back(std::async(std::launch::async, compute_decryption_shares, randomized_ciphertexts, i, std::ref(keys)));
    }

    // Wait till the processing is done
    await_futures(decryption_share_futures);

    // Extract the decryption shares from the clients
    std::vector<std::vector<std::pair<long, ZZ>>> client_decryption_shares;
    client_decryption_shares.reserve(threshold_l + 1);
    for (std::future<std::vector<std::pair<long, ZZ>>> &future : decryption_share_futures) {
        client_decryption_shares.push_back(future.get());
    }

    // 5. Run the combining algorithm
    std::vector<ZZ> decryptions;
    decryptions.reserve(ciphertexts.size());

    for (int i = 0; i < ciphertexts.size(); ++i) {
        std::vector<std::pair<long, ZZ>> ciphertext_decryption_shares;
        ciphertext_decryption_shares.reserve(client_decryption_shares.size());

        for (auto & client_decryption_share : client_decryption_shares) {
            ciphertext_decryption_shares.push_back(client_decryption_share.at(i));
        }

        decryptions.push_back(combine_partial_decrypt(ciphertext_decryption_shares, keys.public_key));
    }

    // 6. Output the final intersection by selecting the elements from the server set that correspond to a decryption of zero
    std::vector<long> intersection;
    for (int i = 0; i < server_set.size(); ++i) {
        if (decryptions.at(i) == 0) {
            intersection.push_back(server_set.at(i));
        }
    }

    return intersection;
}

std::vector<long> threshold_multiparty_psi(std::vector<std::vector<long>> sets,
                                 long threshold_l,
                                 long m_bits, long k_hashes,
                                 long intersection_threshold_T,
                                 Keys &keys) {
    std::vector<std::vector<long>> client_sets;
    client_sets.reserve(sets.size() - 1);
    for (int i = 0; i < sets.size() - 1; ++i) {
        client_sets.push_back(sets.at(i));
    }

    std::vector<long> server_set = sets.at(sets.size() - 1);

    return threshold_multiparty_psi(client_sets, server_set, threshold_l, m_bits, k_hashes, intersection_threshold_T, keys);
}

std::vector<long> threshold_multiparty_psi(std::vector<std::vector<long>> client_sets,
                                          std::vector<long> server_set,
                                          long threshold_l,
                                          long m_bits, long k_hashes,
                                          long intersection_threshold_T, Keys& keys) {
    //// MPSI protocol
    // -> Normally, the keys would be distributed to the parties now
    // TODO: Implement sending


    /// Initialization
    // TODO: Send?


    /// Local EIBF generation

    // 1-3. Clients compute their Bloom filter, invert it and encrypt it (generating EIBFs)
    std::vector<std::vector<ZZ>> client_ebfs;
    client_ebfs.reserve(client_sets.size());
    for (std::vector<long> client_set : client_sets) {
        BloomFilter bloom_filter(m_bits, k_hashes);

        // Step 1
        for (long element : client_set) {
            bloom_filter.insert(element);
        }

        // Step 2
        std::vector<ZZ> eibf;
        bloom_filter.encrypt_all(eibf, keys.public_key);

        client_ebfs.push_back(eibf);
    }

    // 3. Send the encrypted Bloom filters to the server
    // TODO: Implement sending


    /// Set Intersection generation by the server
    // 1-3. Use the k hashes to select elements from the EIBFs and sum them up homomorphically,
    //      rerandomize afterwards.
    std::vector<std::vector<ZZ>> client_ciphertexts;
    client_ciphertexts.reserve(client_sets.size());
    for (int i = 0; i < client_sets.size(); ++i) {
        // Initialize an empty set for each client
        client_ciphertexts.emplace_back();
    }

    for (long element : server_set) {
        // Compute for the first hash function
        unsigned long index = BloomFilter::hash(element, 0) % m_bits;

        std::vector<ZZ> client_ciphertext;
        client_ciphertext.reserve(client_sets.size());
        for (int i = 0; i < client_sets.size(); ++i) {
            client_ciphertext.push_back(client_ebfs.at(i).at(index));
        }

        // Compute for the remaining hash functions
        for (int i = 1; i < k_hashes; ++i) {
            for (int j = 0; j < client_sets.size(); ++j) {
                index = BloomFilter::hash(element, i) % m_bits;

                client_ciphertext.at(j) = add_homomorphically(client_ciphertext.at(j),
                                                              client_ebfs.at(j).at(index),
                                                              keys.public_key);
            }
        }

        // Rerandomize the ciphertext to prevent analysis due to the deterministic nature of homomorphic addition
        for (int i = 0; i < client_sets.size(); ++i) {
            client_ciphertexts.at(i).push_back(rerandomize(client_ciphertext.at(i), keys.public_key));
        }
    }

    // TODO: Send to clients?
    // 4-6. For each ciphertext, compute a fresh encryption of k and run a Secure Comparison Protocol with it
    std::vector<std::vector<ZZ>> client_comparisons;
    client_comparisons.reserve(client_ciphertexts.size());
    for (int i = 0; i < client_ciphertexts.size(); ++i) {
        std::vector<ZZ> comparisons;
        comparisons.reserve(client_ciphertexts.at(i).size());

        for (int j = 0; j < client_ciphertexts.at(i).size(); ++j) {
            comparisons.push_back(multiparty_comparison(encrypt(ZZ(k_hashes), keys.public_key),
                                                        client_ciphertexts.at(i).at(j),
                                                        threshold_l, ZZ(128), keys));
        }

        client_comparisons.push_back(comparisons);
    }

    // 7. Compute the sum of all comparisons belonging to a client and rerandomize
    std::vector<ZZ> summed_comparisons;
    summed_comparisons.reserve(server_set.size());
    for (int i = 0; i < server_set.size(); ++i) {
        // Initialize with the first client
        ZZ sum = client_comparisons.at(0).at(i);

        // Add remaining elements from other clients
        for (int j = 1; j < client_comparisons.size(); ++j) {
            sum = add_homomorphically(sum, client_comparisons.at(j).at(i), keys.public_key);
        }

        // Rerandomize
        summed_comparisons.push_back(rerandomize(sum, keys.public_key));
    }

    // 8-9. Run SCP to compare each summed_comparison with a fresh encryption of intersection_threshold_T and rerandomize again
    std::vector<ZZ> element_ciphertexts;
    element_ciphertexts.reserve(summed_comparisons.size());
    for (auto & summed_comparison : summed_comparisons) {
        std::vector<std::pair<long, ZZ>> yeet;
        yeet.reserve(threshold_l + 1);
        for (int i = 0; i < (threshold_l + 1); ++i) {
            yeet.emplace_back(i + 1, partial_decrypt(summed_comparison, keys.public_key,
                                                                  keys.private_keys.at(i)));
        }

        element_ciphertexts.push_back(rerandomize(
                                 multiparty_comparison(encrypt(ZZ(intersection_threshold_T), keys.public_key),
                                                       summed_comparison,
                                                       threshold_l, ZZ(128), keys),
                                      keys.public_key));
    }

    // 10-11. Collaboratively decrypt each ciphertext and run the combining algorithm
    std::vector<ZZ> decryptions;
    decryptions.reserve(element_ciphertexts.size());
    for (ZZ ciphertext : element_ciphertexts) {
        // Partial decryption (let threshold + 1 parties decrypt)
        std::vector<std::pair<long, ZZ>> decryption_shares;
        decryption_shares.reserve(threshold_l + 1);
        for (int i = 0; i < (threshold_l + 1); ++i) {
            decryption_shares.emplace_back(i + 1, partial_decrypt(ciphertext, keys.public_key,
                                                                  keys.private_keys.at(i)));
        }

        // Combining algorithm
        decryptions.push_back(combine_partial_decrypt(decryption_shares,
                                                      keys.public_key));
    }

    // 12. Output the final intersection by selecting the elements from the server set that correspond to a decryption of one (true)
    std::vector<long> intersection;
    for (int i = 0; i < server_set.size(); ++i) {
        if (decryptions.at(i) == 1) {
            intersection.push_back(server_set.at(i));
        }
    }

    return intersection;
}
