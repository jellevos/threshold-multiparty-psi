//
// Created by jelle on 09-10-20.
//
#include "psi_protocols.h"

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
    std::vector<std::vector<ZZ>> client_eibfs;
    client_eibfs.reserve(client_sets.size());
    for (std::vector<long> client_set : client_sets) {
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

        client_eibfs.push_back(eibf);
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

    // 4-5. Decrypt-to-zero each ciphertext and run the combining algorithm
    std::vector<ZZ> decryptions;
    decryptions.reserve(ciphertexts.size());
    for (ZZ ciphertext : ciphertexts) {
        ZZ zero_ciphertext(1);

        // Client 1 raises C to a nonzero random power and all the clients' results are multiplied
        ZZ random = Gen_Coprime(keys.public_key.n);
        zero_ciphertext = NTL::MulMod(zero_ciphertext,
                                      NTL::PowerMod(ciphertext, random, keys.public_key.n * keys.public_key.n),
                                      keys.public_key.n * keys.public_key.n);
        // Client 2 raises C to a nonzero random power and all the clients' results are multiplied
        random = Gen_Coprime(keys.public_key.n);
        zero_ciphertext = NTL::MulMod(zero_ciphertext,
                                      NTL::PowerMod(ciphertext, random, keys.public_key.n * keys.public_key.n),
                                      keys.public_key.n * keys.public_key.n);

        // TODO: Maybe server as well to make sure it's resistant when clients do not randomize

        // Partial decryption (let threshold + 1 parties decrypt)
        std::vector<std::pair<long, ZZ>> decryption_shares;
        decryption_shares.reserve(threshold_l + 1);
        for (int i = 0; i < (threshold_l + 1); ++i) {
            decryption_shares.emplace_back(i + 1, partial_decrypt(zero_ciphertext, keys.public_key,
                                                                  keys.private_keys.at(i)));
        }

        // Combining algorithm
        decryptions.push_back(combine_partial_decrypt(decryption_shares,
                                                      keys.public_key));
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

std::vector<long> threshold_multiparty_psi(std::vector<std::vector<long>> client_sets,
                                          std::vector<long> server_set,
                                          long threshold_l, long parties_t,
                                          long key_length, long m_bits, long k_hashes,
                                          long intersection_threshold_T) {
    //// MPSI protocol
    Keys keys;
    key_gen(&keys, key_length, threshold_l, parties_t);
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
