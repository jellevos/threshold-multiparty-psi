//
// Created by jelle on 09-10-20.
//

#ifndef PSI_PROTOCOLS_H
#define PSI_PROTOCOLS_H

#include <vector>

std::vector<unsigned long> multiparty_psi(std::vector<std::vector<unsigned long>> client_sets,
                                          std::vector<unsigned long> server_set,
                                          unsigned long threshold_l, unsigned long parties_t,
                                          unsigned long key_length, unsigned long m_bits, unsigned long k_hashes);

#endif //PSI_PROTOCOLS_H
