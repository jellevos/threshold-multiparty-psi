/**
From: https://github.com/ziyao002/Threshold-Paillier-with-ZKP
Adapted by Jelle Vos
*/
#include <iostream>
#include <cstdlib>
#include "threshold_paillier.hpp"

using namespace std;
using namespace NTL;

/* Reference: Fouque, P. A., Poupard, G., & Stern, J. (2000, February). Sharing decryption in the context of voting or lotteries. */

NTL::ZZ Gen_Coprime(const NTL::ZZ& n){
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

NTL::ZZ lcm(const NTL::ZZ& x, const NTL::ZZ& y){
    /* Least common multiple function. Computes the least common multiple of x and y.
     *
     * Parameters
     * ==========
     * NTL::ZZ x, y: signed, arbitrary length integers.
     *
     * Returns
     * =======
     * NTL:ZZ lcm : the least common multiple of x and y.
     */
    NTL::ZZ lcm;
    lcm = (x * y) / NTL::GCD(x,y);
    return lcm;
}

void GenSafePrimePair(NTL::ZZ& p, NTL::ZZ& q, NTL::ZZ& pp, NTL::ZZ& qq, long keyLength){
    /* Coprime generation function. Generates a random coprime number of n.
     *
     * Parameters
     * ==========
     * NTL::ZZ p, q, pp, qq: // p and q are safe primes in the same bit length, i.e., p = 2 * pp + 1 and q = 2 * qq + 1, where pp and qq are primes.
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

Threshold_Paillier::Threshold_Paillier(const long keyLength = 512) {
    /* Threshold Paillier parameters generation function. Generates threshold paillier parameters from scrach.
     *
     * Parameters
     * ==========
     * long keyLength: the length of the key.
     *
     * =======
     * public key  = (modulus, generator, theta).
     * private key = beta * m.
     */
    GenSafePrimePair(p, q, pp, qq, keyLength);								// p and q are safe primes, i.e., p = 2 * pp + 1 and q = 2 * qq + 1, where pp and qq are primes

    // key generation
    modulus = p * q;														// modulus = p * q
    m = pp * qq;															// m = pp * qq
    generator = modulus + 1;												// generator = modulus + 1
    beta = Gen_Coprime(modulus);
    theta = NTL::MulMod(m, beta, modulus);									// theta = m * beta mod modulus
    delta = 6;																// 3 partirs: delta = 3!

    // verification key
    NTL::ZZ r_vk = Gen_Coprime(modulus * modulus);
    vk = NTL::PowerMod(r_vk, 2, modulus * modulus);							// VK = r_vk**2 mod (modulus**2)
    t = 80;																	// t, l: security parameters for ZKP, choose 80 for
    l = 80;

    // secret key distribution
    a1 = RandomBnd(modulus*m);
    a2 = RandomBnd(modulus*m);
    f1 = (beta * m + a1 * 1 + a2 * 1 * 1) % (modulus*m);					// share the secret key, i.e., beta * m, by a random polynomial in F(modulus*m)
    f2 = (beta * m + a1 * 2 + a2 * 2 * 2) % (modulus*m);
    f3 = (beta * m + a1 * 3 + a2 * 3 * 3) % (modulus*m);
    vk1 = NTL::PowerMod(vk, delta * f1, modulus * modulus);					// VKi is public
    vk2 = NTL::PowerMod(vk, delta * f2, modulus * modulus);
    vk3 = NTL::PowerMod(vk, delta * f3, modulus * modulus);

}

NTL::ZZ Threshold_Paillier::encrypt(NTL::ZZ& message){
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
    NTL::ZZ random = Gen_Coprime(modulus);
    NTL::ZZ ciphertext = NTL::PowerMod(generator, message, modulus * modulus) * NTL::PowerMod(random, modulus, modulus * modulus);
    return ciphertext % (modulus * modulus);
}

NTL::ZZ Threshold_Paillier::partial_decrypt( NTL::ZZ& ciphertext, NTL::ZZ& fi){
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
    NTL::ZZ partial_decryption = NTL::PowerMod(ciphertext, 2*delta*fi, modulus * modulus);
    return partial_decryption;
}

NTL::ZZ Threshold_Paillier::combine_partial_decrypt(NTL::ZZ& c1, NTL::ZZ& c2, NTL::ZZ& c3){
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
    NTL::ZZ lamda1, lamda2, lamda3;		// parameters for 3-party Paillier
    lamda1= 3;
    lamda2 = -3;
    lamda3 = 1;
    NTL::ZZ u1 = delta * lamda1;
    NTL::ZZ u2 = delta * lamda2;
    NTL::ZZ u3 = delta * lamda3;
    NTL::ZZ product_1 = NTL::PowerMod(c1, 2*u1, modulus * modulus);
    NTL::ZZ product_2 = NTL::PowerMod(c2, 2*u2, modulus * modulus);
    NTL::ZZ product_3 = NTL::PowerMod(c3, 2*u3, modulus * modulus);
    NTL::ZZ product = NTL::MulMod(NTL::MulMod(product_1, product_2, modulus * modulus), product_3, modulus * modulus);
    NTL::ZZ Inv_temp = NTL::InvMod(4 * delta * delta * theta % modulus, modulus);
    NTL::ZZ M = NTL::MulMod(L_function(product), Inv_temp, modulus);
    return M;
}

void Threshold_Paillier::ZKP_gen_R(NTL::ZZ& c, NTL::ZZ& r, NTL::ZZ& R1, NTL::ZZ& R2){
    /* Pi's R and r generation function for ZKP.
     *
     * Parameters
     * ==========
     * NTL::ZZ c : the decryption of the original massage.
     * NTL::ZZ r : the random parameter used for ZKP in Pi's ZKP_gen_R function and ZKP_comput_z function.
     * NTL::ZZ R1, R2: random parameters used in the procesee of ZKP.
     * NTL::ZZ t, l: the security parameters that (2**t)**-1 and (2**l)**-1 are negligible.
     */
    NTL::ZZ Bound = NTL::power(NTL::ZZ(2), t + l) * modulus * m;
    r = RandomBnd(Bound);
    R1 = NTL::PowerMod(vk, delta * r, modulus * modulus);
    R2 = NTL::PowerMod(c, 4 * delta * r, modulus * modulus);
    return;
}

NTL::ZZ Threshold_Paillier::ZKP_gen_cc(){
    /* Verifier's cc generation function for ZKP.
     *
     * Parameters
     * ==========
     * NTL::ZZ t : the security parameter that (2**t)**-1 is negligible.
     * NTL::ZZ cc : random parameters used for ZKP in ZKP_comput_z function and ZKP_check function.
     */
    NTL::ZZ Bound = NTL::power(NTL::ZZ(2), t);
    NTL::ZZ cc = RandomBnd(Bound);
    return cc;
}

NTL::ZZ Threshold_Paillier::ZKP_comput_z(NTL::ZZ& r, NTL::ZZ& cc, NTL::ZZ& fi){
    /* Pi's z computing function for ZKP.
     *
     * Parameters
     * ==========
     * NTL::ZZ cc: random parameters used in the procesee of ZKP, generated by verifier's ZKP_gen_cc function.
     * NTL::ZZ fi : the Pi's share of secret key, i.e., beta * m.
     */
    NTL::ZZ z = r + cc * fi;
    return z;
}

bool Threshold_Paillier::ZKP_check(NTL::ZZ& c, NTL::ZZ& ci, NTL::ZZ& R1, NTL::ZZ& R2, NTL::ZZ& cc, NTL::ZZ& z, NTL::ZZ& vki){
    /* Verifier's Zero Knowledge Proof checking function for partial decryption.
     *
      * Parameters
     * ==========
     * NTL::ZZ c: the decryption of the original massage.
     * NTL::ZZ ci: the Pi's partial decryption.
     * NTL::ZZ R1, R2: random parameters used in the procesee of ZKP, generated by Pi's ZKP_gen_R function.
     * NTL::ZZ cc: random parameters used in the procesee of ZKP, generated by verifier's ZKP_gen_cc function.
     * NTL::ZZ z: random parameters used in the procesee of ZKP, generated by Pi's ZKP_comput_z function.
     * NTL::ZZ vki: the Pi's verification key.
     *
     * Returns
     * =======
     * bool partial_ZKP_check: the bool value that returns 1 if the partial ZKP is succesful, return 0 if the partial ZKP is failed.
     */
    NTL::ZZ equality_1_left = NTL::PowerMod(vk, delta * z, modulus * modulus);
    NTL::ZZ equality_1_right = NTL::MulMod(R1, NTL::PowerMod(vki, cc, modulus * modulus), modulus * modulus);
    NTL::ZZ equality_2_left = NTL::PowerMod(c, 4 * delta * z, modulus * modulus);
    NTL::ZZ equality_2_right = NTL::MulMod(R2, NTL::PowerMod(ci, 2 * cc, modulus * modulus), modulus * modulus);
    bool partial_ZKP_check = (NTL::compare(equality_1_left, equality_1_right) == 0 and NTL::compare(equality_2_left, equality_2_right) == 0);
    return partial_ZKP_check;
}

bool Threshold_Paillier::ZKP_for_partial_decryption(NTL::ZZ& ciphertext, NTL::ZZ& c1, NTL::ZZ& c2, NTL::ZZ& c3){
    /* Zero Knowledge Proof for partial decryption in interactive Fiat-Shamir heuristic.
     *
     * Parameters
     * ==========
     * NTL::ZZ cipertext : the encryption of the original message.
     * NTL::ZZ c1, c2, c3: the partial decryptions.
     *
     * Returns
     * =======
     * bool ZKP_check: the bool value that returns 1 if the ZKP is succesful, return 0 if the ZKP is failed.
     */
    NTL::ZZ r1, R11, R12, cc1, z1;																			// P1's parameters for ZKP
    ZKP_gen_R(ciphertext, r1, R11, R12);																	// P1 generates R11, R12 and r1, and sends R11, R12 to the verifiers, i.e., P2 and P3
    cc1 = ZKP_gen_cc();																						// Verifier, i.e., P2 and P3, sends cc1 to P1
    z1 = ZKP_comput_z(r1, cc1, f1);																			// P1 computes z1 according to the cc1, r1 and f1
    bool check1 = ZKP_check(ciphertext, c1, R11, R12, cc1, z1, vk1);										// Verifier, i.e., P2 and P3, checks two equalities for ZKP of partial decryption

    NTL::ZZ r2, R21, R22, cc2, z2;																			// P2's parameters for ZKP
    ZKP_gen_R(ciphertext, r2, R21, R22);																	// P2 generates R21, R22 and r2, and sends R21, R22 to the verifiers, i.e., P1 and P3
    cc2 = ZKP_gen_cc();																						// Verifier, i.e., P1 and P3, sends cc2 to P2
    z2 = ZKP_comput_z(r2, cc2, f2);																			// P2 computes z2 according to the cc2, r2 and f2
    bool check2 = ZKP_check(ciphertext, c2, R21, R22, cc2, z2, vk2);										// Verifier, i.e., P1 and P3, checks two equalities for ZKP of partial decryption

    NTL::ZZ r3, R31, R32, cc3, z3;																			// P3's parameters for ZKP
    ZKP_gen_R(ciphertext, r3, R31, R32);																	// P3 generates R31, R32 and r3, and sends R31, R32 to the verifiers, i.e., P1 and P2
    cc3 = ZKP_gen_cc();																						// Verifier, i.e., P1 and P2, sends cc3 to P3
    z3 = ZKP_comput_z(r3, cc3, f3);																			// P3 computes z3 according to the cc3, r3 and f3
    bool check3 = ZKP_check(ciphertext, c3, R31, R32, cc3, z3, vk3);										// Verifier, i.e., P1 and P2, checks two equalities for ZKP of partial decryption

    bool ZKP_check = check1 and check2 and check3;															// ZKP for partial decryption is successful only when all the partial checks are successful

    return ZKP_check;
}
