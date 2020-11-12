//
// Created by jelle on 07-10-20.
// TODO: Change
//
#include "threshold_paillier.h"


// TODO: Consider changing ZZs to references
// TODO: NTL:ZZ to ZZ
// TODO: Generalize towards an arbitrary number of t and l
// TODO: Fix comments (shorten?)
// TODO: Consider rewriting ZZ to ZZ_p (p does not have to be prime)

static void GenSafePrimePair(NTL::ZZ& p, NTL::ZZ& q, NTL::ZZ& pp, NTL::ZZ& qq, long keyLength){
    /* Coprime generation function. Generates a random coprime number of n.
     *
     * Parameters
     * ==========
     * NTL::ZZ p, q, pp, qq: p and q are safe primes in the same bit length, i.e. p = 2 * pp + 1 and q = 2 * qq + 1,
     *                       where pp and qq are primes.
     * long keyLength: the length of the key.
     */
    while (true) {
        long err = 80;
        pp = NTL::GenGermainPrime_ZZ(keyLength/2, err);
        qq = NTL::GenGermainPrime_ZZ(keyLength/2, err);
        while (pp == qq) {
            qq = NTL::GenGermainPrime_ZZ(keyLength/2, err);
        }
        p = 2 * pp + 1;
        q = 2 * qq + 1;
        NTL::ZZ n = p * q;
        NTL::ZZ phi = (p - 1) * (q - 1);
        if (NTL::GCD(n, phi) == 1) return;
    }
}

ZZ Gen_Coprime(const NTL::ZZ& n) {
    /* Coprime generation function. Generates a random coprime number of n.
    *
    * Parameters
    * ==========
    * NTL::ZZ n : a prime number.
    *
    * Returns
    * =======
    * NTL:ZZ ret : a random coprime number of n.
    */
    NTL::ZZ ret;
    while (true) {
        ret = RandomBnd(n);
        if (NTL::GCD(ret, n) == 1) { return ret; }
    }
}

static ZZ L_function(const ZZ& x, const ZZ& n) { return (x - 1) / n; }


void key_gen(Keys* keys, const long key_length, long threshold_l, long parties_t) {
    ZZ p, q, pp, qq;

    GenSafePrimePair(p, q, pp, qq, key_length);

    // General key generation
    ZZ n = p * q;
    ZZ m = pp * qq;
    ZZ g = n + 1;
    ZZ beta = Gen_Coprime(n);
    ZZ theta = NTL::MulMod(m, beta, n);
    ZZ delta(tgamma(parties_t + 1));

    keys->public_key = PublicKey {
        g,
        n,
        n * n,
        theta,
        delta,
        threshold_l
    };

    // Secret key generation
    std::vector<ZZ> coefficients;
    coefficients.reserve(threshold_l);
    for (int i = 0; i < threshold_l; ++i) {
        // Generate the polynomial coefficients
        coefficients.push_back(NTL::RandomBnd(n * m));
    }

    keys->private_keys.reserve(parties_t);
    for (int i = 1; i <= parties_t; ++i) {
        // Calculate the keys from the polynomials
        ZZ key = beta * m;

        for (int j = 0; j < threshold_l; ++j) {
            key += coefficients.at(j) * NTL::power(ZZ(i), j + 1);
        }

        keys->private_keys.push_back(key % (n * m));
    }
}

ZZ encrypt(ZZ message, const PublicKey& public_key) {
    /* Paillier encryption function. Takes in a message in F(modulus), and returns a message in F(modulus**2).
     *
     * Parameters
     * ==========
     * NTL::ZZ message : the message to be encrypted.
     *
     * Returns
     * =======
     * NTL:ZZ ciphertext : the encyrpted message.
     */
    // Encode numbers so that positive numbers map to [0, n/2] and negative numbers to [n/2, n]
    ZZ encoded_message;
    if (message > 0) {
        encoded_message = message;
    } else {
        encoded_message = public_key.n + message;
    }
    NTL::ZZ random = Gen_Coprime(public_key.n);
    // TODO: Use MulMod
    NTL::ZZ ciphertext = NTL::PowerMod(public_key.g, encoded_message, public_key.n_squared) *
            NTL::PowerMod(random, public_key.n, public_key.n_squared);
    return ciphertext % (public_key.n_squared);
}

ZZ partial_decrypt(ZZ& ciphertext, const PublicKey& public_key, ZZ& secret_key) {
    /* Paillier partial decryption function. Takes in a ciphertext in F(modulus**2), and returns a partial decryption in the same space.
     *
      * Parameters
     * ==========
     * NTL::ZZ cipertext : the encryption of the original message.
     * NTL::ZZ fi : the Pi's share of secret key, i.e., beta * m.
     *
     * Returns
     * =======
     * NTL::ZZ partial_decryption : The partial decryption of the original message.
     */
    ZZ partial_decryption = NTL::PowerMod(ciphertext, 2 * public_key.delta * secret_key, public_key.n_squared);
    return partial_decryption;
}

ZZ combine_partial_decrypt(std::vector<std::pair<long, ZZ>> secret_shares, const PublicKey& public_key) {
    /* Combine the partial decryptions to obtain the decryption of the original ciphertext.
     *
     * Parameters
     * ==========
     * NTL::ZZ c1, c2, c3 : the partial decryptions.
     *
     * Returns
     * =======
     * NTL::ZZ M: the decryption of the original message.
     */
    std::vector<ZZ> lambdas;
    // TODO: Correct mistake here in the paper: it says threshold l out of total l, but we should have l+1 out of t
    for (int i = 0; i < (public_key.threshold_l + 1); ++i) {
        ZZ lambda = public_key.delta;

        for (int i_prime = 0; i_prime < (public_key.threshold_l + 1); ++i_prime) {
            if (i != i_prime) {
                if (secret_shares.at(i).first - secret_shares.at(i_prime).first != 0) {
                    lambda *= secret_shares.at(i_prime).first;
                    lambda /= secret_shares.at(i_prime).first - secret_shares.at(i).first;
                }
            }
        }

        lambdas.push_back(lambda);
    }

    ZZ product(1);
    for (int i = 0; i < (public_key.threshold_l + 1); ++i) {
        product = MulMod(product,
                         PowerMod(secret_shares.at(i).second, 2 * lambdas.at(i), public_key.n_squared),
                         public_key.n_squared);
    }

    ZZ Inv_temp = NTL::InvMod(4 * public_key.delta * public_key.delta * public_key.theta % public_key.n, public_key.n);
    ZZ m = NTL::MulMod(L_function(product, public_key.n), Inv_temp, public_key.n);

    if (m > (public_key.n / 2)) {
        m -= public_key.n;
    }

    return m;
//    return ZZ(0);
}

ZZ add_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key) {
    return NTL::MulMod(c1, c2, public_key.n_squared);
}

ZZ subtract_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key) {
    return add_homomorphically(c1, NTL::InvMod(c2, public_key.n_squared), public_key);
}
ZZ multiply_homomorphically(ZZ ciphertext, ZZ scalar, PublicKey& public_key) {
    return NTL::PowerMod(ciphertext, scalar, public_key.n_squared);
}

ZZ rerandomize(ZZ ciphertext, PublicKey& public_key) {
    // Homomorphically add a random encryption of zero to the ciphertext
    return add_homomorphically(ciphertext, encrypt(ZZ(0), public_key), public_key);
}
