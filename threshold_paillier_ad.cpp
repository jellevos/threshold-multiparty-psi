//
// Created by jelle on 07-10-20.
//
#include <vector>
#include <NTL/ZZ.h>
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/vector.h>

using namespace std;
using namespace NTL;

struct PublicKey {
    NTL::ZZ g;
    NTL::ZZ n;
    NTL::ZZ theta;
};

class ThresholdPaillierNew {

public:
    std::pair<PublicKey, std::vector<ZZ>> key_gen(const long key_length) {
        ZZ p, q, pp, qq;

        GenSafePrimePair(p, q, pp, qq, key_length);

        // General key generation
        ZZ n = p * q;
        ZZ m = pp * qq;
        ZZ g = n + 1;
        ZZ beta = Gen_Coprime(n);
        ZZ theta = NTL::MulMod(m, beta, n);
        ZZ delta(6);

        PublicKey public_key {
            g,
            n,
            theta
        };

        // Secret key generation
        ZZ a1 = NTL::RandomBnd(n * m);
        ZZ a2 = NTL::RandomBnd(n * m);
        std::vector<ZZ> private_keys(3);
        private_keys.push_back((beta * m + a1 * 1 + a2 * 1 * 1) % (n * m));
        private_keys.push_back((beta * m + a1 * 2 + a2 * 2 * 2) % (n * m));
        private_keys.push_back((beta * m + a1 * 3 + a2 * 3 * 3) % (n * m));

        return std::pair(public_key, private_keys);
    };

private:
    void GenSafePrimePair(NTL::ZZ& p, NTL::ZZ& q, NTL::ZZ& pp, NTL::ZZ& qq, long keyLength){
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

};
