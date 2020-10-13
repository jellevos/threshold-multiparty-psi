#include <iostream>
#include <vector>
#include "psi_protocols.h"


// TODO: Cache n^2
// TODO: Allow variable set sizes?
int main() {
    std::vector<long> client1_set({1, 3, 5, 7});
    std::vector<long> client2_set({2, 3, 4, 5});
    std::vector<long> server_set({6, 5, 2, 1});

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
                                                            1);

    std::cout << "The resulting threshold set intersection was: { ";
    for (long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl;

    return 0;
}
