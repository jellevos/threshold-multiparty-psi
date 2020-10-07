#include <iostream>
#include <vector>
#include "MurmurHash3.h"

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
            unsigned long h = BloomFilter::hash(element, i);
            //std::cout << "hash(" << element << ", " << i << "): " << h << std::endl;
            unsigned long index = h % this->m_bits;
            //std::cout << "insert index: " << index << std::endl;
            this->storage.at(index) = true;
        }
    }

    /// Checks whether an element appears to have been inserted into the Bloom filter
    bool contains(unsigned long element) {
        //std::cout << "contains" << std::endl;
        for (unsigned long i = 0; i < this->k_hashes; ++i) {
//            std::cout << "containing" << std::endl;
//            std::cout << "h: " << BloomFilter::hash(element, i) % this->m_bits << std::endl;
//            std::cout << "at: " << this->storage.at(BloomFilter::hash(element, i) % this->m_bits) << std::endl;
            unsigned long h = BloomFilter::hash(element, i);
            //std::cout << "hash(" << element << ", " << i << "): " << h << std::endl;
            unsigned long index = h % this->m_bits;
            //std::cout << "contains index: " << index << std::endl;
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
    std::vector<unsigned long> encrypt() {
        // TODO: Add public key and replace unsigned long with ciphertext
        return std::vector<unsigned long>();
    }

    /// Hashes the input with the given seed using MurmurHash3 and returns the first 32 bits as an unsigned long
    static unsigned long hash(unsigned long input, unsigned long seed) {
        unsigned long output[4];

        MurmurHash3_x64_128(&input, (uint32_t) 8, seed, &output);

        return output[0];
    }
};

int main() {
    std::cout << "Hello, World!" << std::endl;
    BloomFilter hello(5, 3);
//    std::cout << hello.storage.at(4) << std::endl;

//    std::cout << "hashes" << std::endl;
//    std::cout << BloomFilter::hash(1, 1) << std::endl;
//    std::cout << BloomFilter::hash(1, 1) << std::endl;
//    std::cout << BloomFilter::hash(1, 2) << std::endl;
//    std::cout << BloomFilter::hash(2, 1) << std::endl;
//    std::cout << BloomFilter::hash(2, 2) << std::endl;
//    std::cout << BloomFilter::hash(1, 2) << std::endl;

    std::cout << "contains" << std::endl;
    std::cout << hello.contains(1) << std::endl;
    hello.insert(1);
    std::cout << hello.contains(1) << std::endl;
    std::cout << hello.contains(2) << std::endl;
//    std::cout << "list" << std::endl;
//    for (int i = 0; i < hello.m_bits; ++i) {
//        std::cout << hello.storage.at(i) << std::endl;
//    }
//    std::cout << "list inverted" << std::endl;
//    hello.invert();
//    for (int i = 0; i < hello.m_bits; ++i) {
//        std::cout << hello.storage.at(i) << std::endl;
//    }


    //// MPSI protocol

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
    std::vector<unsigned long> client1_eibf = client1_bf.encrypt();
    std::vector<unsigned long> client2_eibf = client2_bf.encrypt();

    // 4. Send the encrypted Bloom filters to the server
    // TODO: Implement sending


    /// Set Intersection Computation
    // 1-2. Use the k hashes to select elements from the EIBFs and sum them up homomorphically,
    //      rerandomize afterwards.
    //std::vector<unsigned long> client1_c(k_hashes);
    //unsigned long client1_c = 0;
    std::vector<unsigned long> ciphertexts(server_set.size());
    for (unsigned long element : server_set) {
        unsigned long ciphertext = 0;

        for (int i = 0; i < k_hashes; ++i) {
            unsigned long index = BloomFilter::hash(element, i) % m_bits;

            // HOMOMORPHIC ADDITION
            ciphertext += client1_eibf.at(index);
            ciphertext += client2_eibf.at(index);

            // TODO: Rerandomize

            ciphertexts.push_back(ciphertext);
        }
    }

    // 3. Decrypt-to-zero each ciphertext
    for (unsigned long ciphertext : ciphertexts) {
        // TODO: Let parties decrypt-to-zero
    }

    return 0;
}
