//
// Created by jelle on 07-10-20.
// TODO: Change
//
#include "threshold_paillier.h"


// TODO: Consider changing ZZs to references

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

static ZZ Gen_Coprime(const NTL::ZZ& n){
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


void key_gen(Keys* keys, const long key_length) {
    ZZ p, q, pp, qq;

    GenSafePrimePair(p, q, pp, qq, key_length);

    // General key generation
    ZZ n = p * q;
    ZZ m = pp * qq;
    ZZ g = n + 1;
    ZZ beta = Gen_Coprime(n);
    ZZ theta = NTL::MulMod(m, beta, n);
    ZZ delta(6);

    keys->public_key = PublicKey {
        g,
        n,
        theta,
        delta
    };

    // Secret key generation
    ZZ a1 = NTL::RandomBnd(n * m);
    ZZ a2 = NTL::RandomBnd(n * m);
    keys->private_keys.reserve(3);
    keys->private_keys.push_back((beta * m + a1 * 1 + a2 * 1 * 1) % (n * m));
    keys->private_keys.push_back((beta * m + a1 * 2 + a2 * 2 * 2) % (n * m));
    keys->private_keys.push_back((beta * m + a1 * 3 + a2 * 3 * 3) % (n * m));
};

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
    NTL::ZZ random = Gen_Coprime(public_key.n);
    NTL::ZZ ciphertext = NTL::PowerMod(public_key.g, message, public_key.n * public_key.n) *
            NTL::PowerMod(random, public_key.n, public_key.n * public_key.n);
    return ciphertext % (public_key.n * public_key.n);
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
    ZZ partial_decryption = NTL::PowerMod(ciphertext, 2 * public_key.delta * secret_key, public_key.n * public_key.n);
    return partial_decryption;
}

ZZ combine_partial_decrypt(ZZ& c1, ZZ& c2, ZZ& c3, const PublicKey& public_key) {
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
    ZZ lambda1(3);
    ZZ lambda2(-3);
    ZZ lambda3(1);

    ZZ u1 = public_key.delta * lambda1;
    ZZ u2 = public_key.delta * lambda2;
    ZZ u3 = public_key.delta * lambda3;

    ZZ product_1 = NTL::PowerMod(c1, 2 * u1, public_key.n * public_key.n);
    ZZ product_2 = NTL::PowerMod(c2, 2 * u2, public_key.n * public_key.n);
    ZZ product_3 = NTL::PowerMod(c3, 2 * u3, public_key.n * public_key.n);

    ZZ product = NTL::MulMod(NTL::MulMod(product_1, product_2, public_key.n * public_key.n),
                             product_3, public_key.n * public_key.n);
    ZZ Inv_temp = NTL::InvMod(4 * public_key.delta * public_key.delta * public_key.theta % public_key.n, public_key.n);
    ZZ m = NTL::MulMod(L_function(product, public_key.n), Inv_temp, public_key.n);

    return m;
}

ZZ add_homomorphically(ZZ c1, ZZ c2, PublicKey& public_key) {
    return NTL::MulMod(c1, c2, public_key.n * public_key.n);
}

ZZ rerandomize(ZZ ciphertext, PublicKey& public_key) {
    // Homomorphically add a random encryption of zero to the ciphertext
    return add_homomorphically(ciphertext, encrypt(ZZ(0), public_key), public_key);
}
