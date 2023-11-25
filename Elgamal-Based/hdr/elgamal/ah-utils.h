#ifndef ELGAMAL_AH_UTILS_H
#define ELGAMAL_AH_UTILS_H

/*******************Include Prerequisites******************
#include <openssl/bn.h>              // BIGNUM
#include "../../hdr/elgamal/utils.h" // GamalCiphertext
#include "../../hdr/macros.h"        // SUCCESS
**********************************************************/

int
elgamal_ah_encrypt (
    GamalCiphertext *ciphertext,
    GamalPk                  pk,
    BIGNUM        *bn_plaintext,
    int                 sec_par);

int
elgamal_ah_decrypt (
    BIGNUM        *bn_plaintext,
    GamalKeys              keys,
    GamalCiphertext *ciphertext);

int
elgamal_brute_force_discrete_log (
    BIGNUM *exponent,
    GamalPk      *pk,
    BIGNUM  *element);

int
baby_step_giant_step(
    BIGNUM *bn_plaintext);

int
elgamal_skip_dlog_check_is_one (
    int           *matched,
    GamalKeys         keys,
    GamalCiphertext cipher);

#endif//ELGAMAL_AH_UTILS_H
