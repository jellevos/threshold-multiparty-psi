//
// Created by jelle on 09-10-20.
//

#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <vector>
#include "threshold_paillier.h"
#include "MurmurHash3.h"

using namespace NTL;

class BloomFilter {
public:
    explicit BloomFilter(unsigned long m_bits, unsigned long k_hashes) :
            storage(m_bits),
            m_bits(m_bits),
            k_hashes(k_hashes) {}

    void insert(long element);
    bool contains(long element);
    void invert();
    void encrypt_all(std::vector<ZZ> &ciphertexts, PublicKey &public_key);
    static long hash(long input, long seed);

private:
    std::vector<bool> storage;  // TODO: Make private
    unsigned long m_bits;
    unsigned long k_hashes;
};

#endif //BLOOM_FILTER_H
