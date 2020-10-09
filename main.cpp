#include <iostream>
#include <vector>
#include "threshold_paillier.h"
#include "bloom_filter.h"


// TODO: Cache n^2
// TODO: Move protocol to separate file
int main() {
    //// MPSI protocol
    Keys keys;
    key_gen(&keys, 512);
    // -> Normally, the keys would be distributed to the parties now
    // TODO: Implement sending


    /// Initialization
    unsigned long m_bits = 16;
    unsigned long k_hashes = 4;


    /// Local EIBF generation
    std::vector<unsigned long> client1_set({1, 2, 3});
    std::vector<unsigned long> client2_set({2, 3, 4});
    std::vector<unsigned long> server_set({5, 3, 2});

    // 1. Clients computer their Bloom filter
    BloomFilter client1_bf(m_bits, k_hashes);
    BloomFilter client2_bf(m_bits, k_hashes);
    for (unsigned long element : client1_set) {
        client1_bf.insert(element);
    }
    for (unsigned long element : client2_set) {
        client2_bf.insert(element);
    }

    // 2. Invert the Boom filters
    client1_bf.invert();
    client2_bf.invert();

    // 3. Compute the encrypted (inverted) Bloom filters
    std::vector<ZZ> client1_eibf;
    std::vector<ZZ> client2_eibf;
    client1_bf.encrypt_all(client1_eibf, keys.public_key);
    client2_bf.encrypt_all(client2_eibf, keys.public_key);

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
        ZZ ciphertext = client1_eibf.at(index);
        ciphertext = add_homomorphically(ciphertext, client2_eibf.at(index), keys.public_key);

        // Compute for the remaining hash functions
        for (int i = 1; i < k_hashes; ++i) {
            index = BloomFilter::hash(element, i) % m_bits;

            // Sum up all selected ciphertexts
            ciphertext = add_homomorphically(ciphertext, client1_eibf.at(index), keys.public_key);
            ciphertext = add_homomorphically(ciphertext, client2_eibf.at(index), keys.public_key);
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

        // Partial decryption
        std::vector<std::pair<unsigned long, ZZ>> decryption_shares;
        decryption_shares.reserve(3);
        // Client 1
        decryption_shares.emplace_back(1, partial_decrypt(zero_ciphertext, keys.public_key, keys.private_keys.at(0)));
        // Client 2
        decryption_shares.emplace_back(2, partial_decrypt(zero_ciphertext, keys.public_key, keys.private_keys.at(1)));
        // Server
        decryption_shares.emplace_back(3, partial_decrypt(zero_ciphertext, keys.public_key, keys.private_keys.at(2)));

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

    return 0;
}
