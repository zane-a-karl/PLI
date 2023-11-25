#ifndef ECELGAMAL_AH_UTILS_H
#define ECELGAMAL_AH_UTILS_H

/*******************Include Prerequisites******************
#include <openssl/ec.h>                // EC_POINT
#include "../../hdr/ecelgamal/utils.h" // EcGamalCiphertext
#include "../../hdr/macros.h"          // SUCCESS
**********************************************************/

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
    int             *matched,
    EcGamalKeys         keys,
    EcGamalCiphertext cipher);

#endif//ECELGAMAL_AH_UTILS_H
