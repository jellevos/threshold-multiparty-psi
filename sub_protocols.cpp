//
// Created by jelle on 11-10-20.
//

#include "sub_protocols.h"

ZZ multiparty_comparison(ZZ a, ZZ b, unsigned long threshold_l, Keys &keys) {
    /// Designed in "Performance Comparison of Secure Comparison Protocols" by Kerschbaum, Biswas and De Hoogh

    // 1. Party X_1 computes the encryption of c = r(x_0 - x_1) - r', where r and r' are random
    ZZ r = Gen_Coprime(keys.public_key.n);
    ZZ r_prime = Gen_Coprime(keys.public_key.n);  // TODO: Make sure r_prime < r

    ZZ difference = subtract_homomorphically(a, b, keys.public_key);
    ZZ c_encrypted = subtract_homomorphically(multiply_homomorphically(difference, r, keys.public_key),
                                              encrypt(r_prime, keys.public_key),
                                              keys.public_key);

    // 2. Send ciphertexts to other parties, with a_1 = Enc(0), a_2 = Enc(1), (a_3 = c_encrypted)
    ZZ a_1 = encrypt(ZZ(0), keys.public_key);
    ZZ a_2 = encrypt(ZZ(1), keys.public_key);
    // TODO: Send

    // 3. Let each party take a turn in re-randomizing and possibly permuting the three ciphertexts
    for (int i = 0; i < threshold_l; ++i) {
        bool b_i = rand() % 2;  // TODO: Check randomness
        if (b_i) {
            // Swap a_1 and a_2 with uniform probability
            std::swap(a_1, a_2);
        }

        a_1 = rerandomize(a_1, keys.public_key);
        a_2 = rerandomize(a_2, keys.public_key);

        r = Gen_Coprime(keys.public_key.n);
        r_prime = Gen_Coprime(keys.public_key.n);  // TODO: Make sure r_prime < r

        c_encrypted = multiply_homomorphically(c_encrypted, ZZ((b_i * 2 - 1) * r), keys.public_key);
        c_encrypted = add_homomorphically(c_encrypted,
                                          encrypt(ZZ(((1 - b_i) * 2 - 1) * r_prime), keys.public_key),
                                          keys.public_key);
        // TODO: Send to next
    }

    std::vector<std::pair<unsigned long, ZZ>> decryption_shares;
    decryption_shares.reserve(3);
    for (int i = 0; i < (threshold_l + 1); ++i) {
        decryption_shares.emplace_back(i + 1, partial_decrypt(c_encrypted, keys.public_key,
                                                              keys.private_keys.at(i)));
    }

    if (combine_partial_decrypt(decryption_shares, keys.public_key) <= 0) {
        return a_1;
    } else {
        return a_2;
    }
}
