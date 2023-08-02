#ifndef _ELGAMAL_MH_UTILS_H_
#define _ELGAMAL_MH_UTILS_H_

#include "utils.h"


int
elgamal_mh_encrypt (
    GamalCiphertext *cipher,
    GamalPk              pk,
    BIGNUM    *bn_plaintext,
    int             sec_par);

int
elgamal_mh_decrypt (
    BIGNUM    *bn_plaintext,
    GamalKeys          keys,
    GamalCiphertext  cipher);

int
elgamal_skip_decrypt_check_equality (
    GamalKeys         keys,
    GamalCiphertext cipher);

#endif//_ELGAMAL_MH_UTILS_H_
