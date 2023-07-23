#ifndef _ELGAMAL_UTILS_H_
#define _ELGAMAL_UTILS_H_

#include <openssl/bn.h>
#include "../hdr/utils.h"


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
parse_hardcoded_bignum (BIGNUM      **output,
			const char *filename);

int
generate_elgamal_keys (GamalKeys *keys);

int
elgamal_mul (GamalCiphertext *res,
	     GamalCiphertext    a,
	     GamalCiphertext    b,
	     BIGNUM      *modulus);

int
elgamal_exp (GamalCiphertext *res,
	     GamalCiphertext    a,
	     BIGNUM     *exponent,
	     BIGNUM      *modulus);

#endif//_ELGAMAL_UTILS_H_
