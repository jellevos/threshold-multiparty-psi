//
// Created by jelle on 11-10-20.
//

#ifndef SUB_PROTOCOLS_H
#define SUB_PROTOCOLS_H

#include "NTL/ZZ.h"
#include "threshold_paillier.h"

using namespace NTL;


// TODO: Check whether Gen_Coprime is really necessary

/// Inputs ciphertexts a and b and returns a ciphertext representing the boolean a <= b (a less than or equal to b)
ZZ multiparty_comparison(ZZ a, ZZ b, long threshold_l, ZZ random_bound, Keys &keys);


#endif //SUB_PROTOCOLS_H
