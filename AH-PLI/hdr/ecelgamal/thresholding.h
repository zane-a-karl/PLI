#ifndef _ECELGAMAL_THRESHOLDING_H_
#define _ECELGAMAL_THRESHOLDING_H_

#include "utils.h"


int
ecelgamal_server_brute_force_thresholding(
    int                     fd,
    EcGamalKeys    server_keys,
    EcGamalCiphertext cipher[],
    InputArgs               ia);

int
ecelgamal_client_brute_force_thresholding (
    int                     fd,
    EcGamalPk        server_pk,
    EcGamalCiphertext cipher[],
    InputArgs               ia);

#endif//_ECELGAMAL_THRESHOLDING_H_
