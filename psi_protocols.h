//
// Created by jelle on 09-10-20.
//

#ifndef PSI_PROTOCOLS_H
#define PSI_PROTOCOLS_H

#include <vector>
#include "threshold_paillier.h"
#include "bloom_filter.h"
#include "sub_protocols.h"

std::vector<long> multiparty_psi(std::vector<std::vector<long>> client_sets, std::vector<long> server_set,
                                 long threshold_l,
                                 long m_bits, long k_hashes,
                                 Keys &keys);

std::vector<long> multiparty_psi(std::vector<std::vector<long>> sets,
                                 long threshold_l,
                                 long m_bits, long k_hashes,
                                 Keys &keys);

std::vector<long> threshold_multiparty_psi(std::vector<std::vector<long>> sets,
                                           long threshold_l,
                                           long m_bits, long k_hashes,
                                           long intersection_threshold_T,
                                           Keys &keys);

std::vector<long> threshold_multiparty_psi(std::vector<std::vector<long>> client_sets,
                                           std::vector<long> server_set,
                                           long threshold_l,
                                           long m_bits, long k_hashes,
                                           long intersection_threshold_T, Keys& keys);
#endif //PSI_PROTOCOLS_H
