#ifndef _ELGAMAL_UTILS_H_
#define _ELGAMAL_UTILS_H_

#include <openssl/bn.h>

#define SUCCESS 1
#define FAILURE 0

typedef struct GamalPk {
    /* BIGNUM *group; // unneeded*/
    BIGNUM *modulus;
    BIGNUM *generator;
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
generate_elgamal_keys (GamalKeys *keys);

int
elgamal_mul (GamalCiphertext *res,
	     GamalCiphertext   *a,
	     GamalCiphertext   *b,
	     BIGNUM      *modulus);

int
elgamal_exp (GamalCiphertext *res,
	     GamalCiphertext   *a,
	     BIGNUM     *exponent,
	     BIGNUM      *modulus);

#endif//_ELGAMAL_UTILS_H_