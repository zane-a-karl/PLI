#ifndef _ELEGAMAL_THRESHOLDING_H_
#define _ELEGAMAL_THRESHOLDING_H_

#include "utils.h"


int
elgamal_server_thresholding(
    size_t          *matches,
    int                   fd,
    GamalKeys    server_keys,
    GamalCiphertext cipher[],
    InputArgs             ia);

int
elgamal_client_thresholding (
    int                   fd,
    GamalPk        server_pk,
    GamalCiphertext cipher[],
    InputArgs             ia);

#endif//_ELEGAMAL_THRESHOLDING_H_
