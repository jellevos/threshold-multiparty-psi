#include <iostream>
#include <vector>
#include "psi_protocols.h"


// TODO: Cache n^2
int main() {
    std::cout << "Computing the set intersection between multiple parties using a (2, 3)-encryption of 1024 bits."
    << std::endl;

    std::vector<unsigned long> client1_set({1, 2, 3});
    std::vector<unsigned long> client2_set({2, 3, 4});
    std::vector<unsigned long> server_set({5, 3, 2});

    std::vector<unsigned long> result = multiparty_psi(std::vector({client1_set, client2_set}),
                                                       server_set,
                                                       2, 3,
                                                       1024,
                                                       16, 4);

    std::cout << "The resulting set intersection was: { ";
    for (unsigned long element : result) {
        std::cout << element << " ";
    }
    std::cout << "}." << std::endl;

    return 0;
}
