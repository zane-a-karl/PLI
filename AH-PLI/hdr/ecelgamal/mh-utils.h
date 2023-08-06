#ifndef _ECELGAMAL_MH_H_
#define _ECELGAMAL_MH_H_

#include "utils.h"


int
ecelgamal_mh_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par);

int
ecelgamal_mh_decrypt (
    BIGNUM          *bn_plain,
    EcGamalKeys          keys,
    EcGamalCiphertext  cipher);

int
ecelgamal_skip_decrypt_check_equality (
    EcGamalKeys       keys,
    EcGamalCiphertext cipher,
    int             *matches);

#endif//_ECELGAMAL_MH_H_
