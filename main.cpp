#include <iostream>
#include <vector>
#include "MurmurHash3.h"
#include "threshold_paillier.h"

class BloomFilter {
public:
    explicit BloomFilter(unsigned long m_bits, unsigned long k_hashes) :
    storage(m_bits),
    m_bits(m_bits),
    k_hashes(k_hashes) {}

    std::vector<bool> storage;  // TODO: Make private
    unsigned long m_bits;
    unsigned long k_hashes;

    /// Inserts the given element into the Bloom filter
    void insert(unsigned long element) {
        std::cout << "insert" << std::endl;
        for (unsigned long i = 0; i < this->k_hashes; ++i) {
            unsigned long index = BloomFilter::hash(element, i) % this->m_bits;
            this->storage.at(index) = true;
        }
    }

    /// Checks whether an element appears to have been inserted into the Bloom filter
    bool contains(unsigned long element) {
        for (unsigned long i = 0; i < this->k_hashes; ++i) {
            unsigned long index = BloomFilter::hash(element, i) % this->m_bits;
            if (not this->storage.at(index)) {
                return false;
            }
        }

        return true;
    }

    /// Inverts the Bloom filter in place so that all 0s become 1s and all 1s become 0s
    void invert() {
        for (unsigned long j = 0; j < this->m_bits; ++j) {
            this->storage.at(j) = !this->storage.at(j);
        }
    }

    /// Returns the bit-by-bit ciphertexts of the encrypted Bloom filter
    void encrypt_all(std::vector<ZZ> &ciphertexts, PublicKey &public_key) {
        ciphertexts.reserve(this->storage.size());
        for (int i = 0; i < this->storage.size(); ++i) {
            // TODO: Maybe cast storage to long
            ciphertexts.at(i) = encrypt(ZZ(this->storage.at(i)), public_key);
        }
    }

    /// Hashes the input with the given seed using MurmurHash3 and returns the first 32 bits as an unsigned long
    static unsigned long hash(unsigned long input, unsigned long seed) {
        unsigned long output[4];

        MurmurHash3_x64_128(&input, (uint32_t) 8, seed, &output);

        return output[0];
    }
};

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
    std::vector<ZZ> ciphertexts(server_set.size());
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

            // TODO: Rerandomize

            ciphertexts.push_back(ciphertext);
        }
    }

    // 3. Decrypt-to-zero each ciphertext
    for (ZZ ciphertext : ciphertexts) {
        // TODO: Let parties decrypt-to-zero
    }

    return 0;
}
