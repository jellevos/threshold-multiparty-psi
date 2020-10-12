//
// Created by jelle on 09-10-20.
//

#include "bloom_filter.h"


/// Inserts the given element into the Bloom filter
void BloomFilter::insert(long element) {
    for (unsigned long i = 0; i < this->k_hashes; ++i) {
        unsigned long index = BloomFilter::hash(element, i) % this->m_bits;
        this->storage.at(index) = true;
    }
}

/// Checks whether an element appears to have been inserted into the Bloom filter
bool BloomFilter::contains(long element) {
    for (unsigned long i = 0; i < this->k_hashes; ++i) {
        long index = BloomFilter::hash(element, i) % this->m_bits;
        if (not this->storage.at(index)) {
            return false;
        }
    }

    return true;
}

/// Inverts the Bloom filter in place so that all 0s become 1s and all 1s become 0s
void BloomFilter::invert() {
    for (long j = 0; j < this->m_bits; ++j) {
        this->storage.at(j) = !this->storage.at(j);
    }
}

/// Returns the bit-by-bit ciphertexts of the encrypted Bloom filter
// TODO: Consider not passing ciphertexts by reference
void BloomFilter::encrypt_all(std::vector<ZZ> &ciphertexts, PublicKey &public_key) {
    ciphertexts.reserve(this->storage.size());
    for (bool element : this->storage) {
        // TODO: Maybe cast storage to long
        ciphertexts.push_back(encrypt(ZZ(element), public_key));
    }
}

/// Hashes the input with the given seed using MurmurHash3 and returns the first 32 bits as an unsigned long
long BloomFilter::hash(long input, long seed) {
    unsigned long output[4];

    MurmurHash3_x64_128(&input, (uint32_t) 8, seed, &output);

    return output[0];
}
