#ifndef ECELGAMAL_MH_UTILS_H
#define ECELGAMAL_MH_UTILS_H

/*******************Include Prerequisites******************
#include <openssl/ec.h>                // EC_POINT
#include "../../hdr/ecelgamal/utils.h" // EcGamalCiphertext
#include "../../hdr/macros.h"          // SUCCESS
**********************************************************/

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
    int             *matched,
    EcGamalKeys         keys,
    EcGamalCiphertext cipher);

#endif//ECELGAMAL_MH_UTILS_H
