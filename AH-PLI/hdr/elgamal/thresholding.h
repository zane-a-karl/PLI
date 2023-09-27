#ifndef _THRESHOLDING_H_
#define _THRESHOLDING_H_

#include "utils.h"
#include <openssl/sha.h>

int
elgamal_server_brute_force_thresholding (
    int                   fd,
    GamalKeys    server_keys,
    GamalCiphertext cipher[],
    InputArgs             ia,
    int          num_entries);

int
elgamal_client_brute_force_thresholding (
    int                   fd,
    GamalPk        server_pk,
    GamalCiphertext cipher[],
    InputArgs             ia,
    int          num_entries);

#endif//_THRESHOLDING_H_
