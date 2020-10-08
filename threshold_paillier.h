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
    ZZ theta;
    ZZ delta;
};

struct Keys {
    PublicKey public_key;
    std::vector<ZZ> private_keys;
};

void key_gen(Keys* keys, long key_length);
ZZ encrypt(ZZ message, const PublicKey& public_key);
ZZ partial_decrypt(ZZ& ciphertext, const PublicKey& public_key, ZZ& secret_key);
ZZ combine_partial_decrypt(ZZ& c1, ZZ& c2, ZZ& c3, const PublicKey& public_key);
ZZ add_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key);
ZZ rerandomize(ZZ ciphertext, PublicKey& public_key);

#endif //THRESHOLD_PAILLIER_H
