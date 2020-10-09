//
// Created by jelle on 09-10-20.
//

#include "psi_protocols.h"
#include "threshold_paillier.h"
#include "bloom_filter.h"

std::vector<unsigned long> multiparty_psi(std::vector<std::vector<unsigned long>> client_sets,
                                          std::vector<unsigned long> server_set,
                                          unsigned long threshold_l, unsigned long parties_t,
                                          unsigned long key_length, unsigned long m_bits, unsigned long k_hashes) {
    //// MPSI protocol
    Keys keys;
    key_gen(&keys, 512, threshold_l, parties_t);
    // -> Normally, the keys would be distributed to the parties now
    // TODO: Implement sending


    /// Initialization
//    unsigned long m_bits = 16;
//    unsigned long k_hashes = 4;
    // TODO: Send?


    /// Local EIBF generation
//    std::vector<unsigned long> client1_set({1, 2, 3});
//    std::vector<unsigned long> client2_set({2, 3, 4});
//    std::vector<unsigned long> server_set({5, 3, 2});

    // 1-3. Clients compute their Bloom filter, invert it and encrypt it (generating EIBFs)
    std::vector<std::vector<ZZ>> client_eibfs;
    client_eibfs.reserve(client_sets.size());
    for (std::vector<unsigned long> client_set : client_sets) {
        BloomFilter bloom_filter(m_bits, k_hashes);

        // Step 1
        for (unsigned long element : client_set) {
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
    for (unsigned long element : server_set) {
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
        std::vector<std::pair<unsigned long, ZZ>> decryption_shares;
        decryption_shares.reserve(3);
        for (int i = 0; i < (threshold_l + 1); ++i) {
            decryption_shares.emplace_back(i + 1, partial_decrypt(zero_ciphertext, keys.public_key,
                                                                  keys.private_keys.at(i)));
        }

        // Combining algorithm
        decryptions.push_back(combine_partial_decrypt(decryption_shares,
                                                      keys.public_key));
    }

    // 6. Output the final intersection by selecting the elements from the server set that correspond to a decryption of zero
    std::vector<unsigned long> intersection;
    for (int i = 0; i < server_set.size(); ++i) {
        if (decryptions.at(i) == 0) {
            intersection.push_back(server_set.at(i));
        }
    }

    return intersection;
}
