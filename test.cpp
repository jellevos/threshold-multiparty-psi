//
// Created by jelle on 07-10-20.
//
#include <iostream>
#include "threshold_paillier.hpp"
#include "threshold_paillier_ad.cpp"

using namespace NTL;

int main() {
    std::cout << "hi" << std::endl;
//    Threshold_Paillier threshold_paillier(512);											// key generation and distribution
//
//    ZZ message(34614984);																	// plaintext massage
//
//    ZZ c = threshold_paillier.encrypt(message);											// ciphertext c = encryption(massage)
//
//    ZZ c1 = threshold_paillier.partial_decrypt(c, threshold_paillier.f1);				// partial decryption
//    ZZ c2 = threshold_paillier.partial_decrypt(c, threshold_paillier.f2);
//    ZZ c3 = threshold_paillier.partial_decrypt(c, threshold_paillier.f3);
//
//    bool ZKP_check = threshold_paillier.ZKP_for_partial_decryption(c, c1, c2, c3);		// ZKP for partial decryption
//    if(ZKP_check){std::cout << "ZKP for partial decrpytion is successful" << std::endl;}
//    else{std::cout << "ZKP for partial decryption is failed" << std::endl;}
//
//    ZZ dec_c = threshold_paillier.combine_partial_decrypt(c1, c2, c3);					// combine partial decryptions
//
//    if (dec_c == message){
//        std::cout << "Encryption and distributed decryption is successful" << std::endl;
//    }
    Keys keys;
    ThresholdPaillierNew::key_gen(&keys, 512);

    ZZ message(34614984);

    ZZ c = ThresholdPaillierNew::encrypt(message, keys.public_key);

    ZZ c1 = ThresholdPaillierNew::partial_decrypt(c, keys.public_key, keys.private_keys.at(0));
    ZZ c2 = ThresholdPaillierNew::partial_decrypt(c, keys.public_key, keys.private_keys.at(1));
    ZZ c3 = ThresholdPaillierNew::partial_decrypt(c, keys.public_key, keys.private_keys.at(2));

    ZZ dec_c = ThresholdPaillierNew::combine_partial_decrypt(c1, c2, c3, keys.public_key);

    if (dec_c == message){
        std::cout << "Encryption and distributed decryption is successful" << std::endl;
    }

    return 0;
}
