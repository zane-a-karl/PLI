#ifndef _ECELGAMAL_AH_UTILS_H_
#define _ECELGAMAL_AH_UTILS_H_

#include "utils.h"


int
ecelgamal_ah_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par);

int
ecelgamal_brute_force_discrete_log (
    BIGNUM  *exponent,
    EcGamalPk     *pk,
    EC_POINT *element);

int
ecelgamal_ah_decrypt (
    BIGNUM          *bn_plain,
    EcGamalKeys          keys,
    EcGamalCiphertext  cipher);

int
ecelgamal_skip_dlog_check_is_at_infinity (
    EcGamalKeys         keys,
    EcGamalCiphertext cipher,
    int             *matches);

#endif//_ECELGAMAL_AH_UTILS_H_
