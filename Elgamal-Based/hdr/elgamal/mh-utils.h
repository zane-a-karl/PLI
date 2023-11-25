#ifndef ELGAMAL_MH_UTILS_H
#define ELGAMAL_MH_UTILS_H

/*******************Include Prerequisites******************
#include "../../hdr/elgamal/utils.h" // GamalCiphertext
#include "../../hdr/macros.h"        // SUCCESS
**********************************************************/

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
    int           *matched,
    GamalKeys         keys,
    GamalCiphertext cipher);

#endif//ELGAMAL_MH_UTILS_H
