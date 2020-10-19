//
// Created by jelle on 07-10-20.
//

#ifndef THRESHOLD_PAILLIER_H
#define THRESHOLD_PAILLIER_H

#include <vector>
#include <NTL/ZZ.h>

using namespace NTL;

struct PublicKey {
    ZZ g;
    ZZ n;
    ZZ n_squared;
    ZZ theta;
    ZZ delta;
    long threshold_l;
};

struct Keys {
    PublicKey public_key;
    std::vector<ZZ> private_keys;
};

void key_gen(Keys* keys, long key_length, long threshold_l, long parties_t);
ZZ encrypt(ZZ message, const PublicKey& public_key);
ZZ partial_decrypt(ZZ& ciphertext, const PublicKey& public_key, ZZ& secret_key);
ZZ combine_partial_decrypt(std::vector<std::pair<long, ZZ>> secret_shares, const PublicKey& public_key);
ZZ add_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key);
ZZ subtract_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key);
ZZ multiply_homomorphically(ZZ ciphertext, ZZ scalar, PublicKey& public_key);
ZZ rerandomize(ZZ ciphertext, PublicKey& public_key);
ZZ Gen_Coprime(const NTL::ZZ& n);

#endif //THRESHOLD_PAILLIER_H
