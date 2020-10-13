#include <iostream>
#include <vector>
#include "psi_protocols.h"
#include "sub_protocols.h"


// TODO: Cache n^2
// TODO: Allow variable set sizes?
int main() {
    Keys keys;
    key_gen(&keys, 1024, 3, 4);
    // TODO: Important! Rewrite to long instead of unsigned long, use upper half of modulus as negative range
    // It needs to hold that key_length > 2^random_bound + 2^input_length + 4
    std::cout << multiparty_comparison(encrypt(ZZ(7), keys.public_key),
                                       encrypt(ZZ(6), keys.public_key),
                                       3, ZZ(256), keys) << std::endl;


    std::vector<long> client1_set({1, 3, 5});
    std::vector<long> client2_set({3, 4, 5});
    std::vector<long> server_set({5, 3, 2});

    std::cout << "Computing the set intersection between multiple parties using a (2, 3)-encryption of 1024 bits."
              << std::endl;

    std::vector<long> result = multiparty_psi(std::vector({client1_set, client2_set}), server_set,
                                              2, 3,
                                              1024,
                                              16, 4);

    std::cout << "The resulting set intersection was: { ";
    for (long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl << std::endl;


    std::cout << "Computing the threshold set intersection between multiple parties using a (2, 3)-encryption of 1024 bits."
              << std::endl;

    result = threshold_multiparty_psi(std::vector({client1_set, client2_set}), server_set,
                                                            2, 3,
                                                            1024,
                                                            16, 4,
                                                            2);

    std::cout << "The resulting threshold set intersection was: { ";
    for (long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl;

    return 0;
}
