#ifndef _ELGAMAL_UTILS_H_
#define _ELGAMAL_UTILS_H_

#include <openssl/bn.h>
#include "../utils.h"


typedef struct GamalPk {
    BIGNUM *generator;
    BIGNUM *modulus;
    BIGNUM *mul_mask;
} GamalPk;

typedef struct GamalSk {
    BIGNUM *secret;
} GamalSk;

typedef struct GamalKeys {
    GamalPk *pk;
    GamalSk *sk;
} GamalKeys;

typedef struct GamalCiphertext {
    BIGNUM *c1;
    BIGNUM *c2;
} GamalCiphertext;

int
parse_hardcoded_bignum (
    BIGNUM      **output,
    int          sec_par,
    const char *filename);

int
elgamal_generate_keys (
    GamalKeys *keys,
    int     sec_par);

int
elgamal_mul (
    GamalCiphertext *res,
    GamalCiphertext    a,
    GamalCiphertext    b,
    BIGNUM      *modulus);

int
elgamal_exp (
    GamalCiphertext *res,
    GamalCiphertext    a,
    BIGNUM     *exponent,
    BIGNUM      *modulus);

int
elgamal_permute_ciphertexts (
    GamalCiphertext **ctxts,
    unsigned long       len);

int
elgamal_send_pk (
    int        sockfd,
    GamalPk       *pk,
    char *conf_prefix);

int
elgamal_send_ciphertext (
    int         sockfd,
    GamalCiphertext *c,
    char  *conf_prefix);


int
elgamal_recv_pk (
    int        sockfd,
    GamalPk       *pk,
    char *conf_prefix);

int
elgamal_recv_ciphertext (
    int         sockfd,
    GamalCiphertext *c,
    char  *conf_prefix);

#endif//_ELGAMAL_UTILS_H_
