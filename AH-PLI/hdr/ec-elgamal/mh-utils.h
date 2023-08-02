#ifndef _EC_ELGAMAL_MH_H_
#define _EC_ELGAMAL_MH_H_

#include "../utils.h"
#include "utils.h"


int
mh_ec_elgamal_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par);

int
mh_ec_elgamal_decrypt (
    BIGNUM          *bn_plain,
    EcGamalKeys          keys,
    EcGamalCiphertext  cipher);

int
ec_elgamal_skip_decrypt_check_equality (
    EcGamalKeys       keys,
    EcGamalCiphertext cipher);

#endif//_EC_ELGAMAL_MH_H_
