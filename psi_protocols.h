//
// Created by jelle on 09-10-20.
//

#ifndef PSI_PROTOCOLS_H
#define PSI_PROTOCOLS_H

#include <vector>

std::vector<long> multiparty_psi(std::vector<std::vector<long>> client_sets, std::vector<long> server_set,
                                 long threshold_l, long parties_t,
                                 long key_length, long m_bits, long k_hashes);

#endif //PSI_PROTOCOLS_H
