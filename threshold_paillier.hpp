/**
From: https://github.com/ziyao002/Threshold-Paillier-with-ZKP
Adapted by Jelle Vos
*/
#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/vector.h>

class Threshold_Paillier {
public:
    Threshold_Paillier(const long keyLength);

    NTL::ZZ encrypt(NTL::ZZ& message);
    NTL::ZZ partial_decrypt(NTL::ZZ& ciphertext, NTL::ZZ& fi);
    NTL::ZZ combine_partial_decrypt(NTL::ZZ& c1, NTL::ZZ& c2, NTL::ZZ& c3);

    void ZKP_gen_R(NTL::ZZ& c, NTL::ZZ& r1, NTL::ZZ& R1, NTL::ZZ& R2);
    NTL::ZZ ZKP_gen_cc();
    NTL::ZZ ZKP_comput_z(NTL::ZZ& r, NTL::ZZ& cc, NTL::ZZ& fi);
    bool ZKP_check(NTL::ZZ& c, NTL::ZZ& ci, NTL::ZZ& R1, NTL::ZZ& R2, NTL::ZZ& z, NTL::ZZ& cc, NTL::ZZ& vki);
    bool ZKP_for_partial_decryption(NTL::ZZ& cc_massage, NTL::ZZ& c1, NTL::ZZ& c2, NTL::ZZ& c3);

    NTL::ZZ modulus;			// public
    NTL::ZZ generator;			// public
    NTL::ZZ theta;				// public
    NTL::ZZ m;					// public
    NTL::ZZ delta;				// public
    NTL::ZZ f1, f2, f3;			// fi is private to Pi

    NTL::ZZ vk;					// public
    NTL::ZZ vk1, vk2, vk3;		// public
    long t, l;					// public

private:
    NTL::ZZ p, q, pp, qq;		// private to the trust dealer
    NTL::ZZ beta;				// private to the trust dealer
    NTL::ZZ a1, a2;				// private to the trust dealer

    NTL::ZZ L_function(const NTL::ZZ& x) { return (x - 1) / modulus; }
};
