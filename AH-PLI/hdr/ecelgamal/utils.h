#ifndef _ECELGAMAL_UTILS_H_
#define _ECELGAMAL_UTILS_H_

#include <openssl/bn.h> // BIGNUM
#include <openssl/ec.h> // EC_POINT
#include <openssl/obj_mac.h> // NID's
#include "../utils.h"

/* Find Available Curves with `openssl ecparam -list_curves` */
#define OPENSSL_160_BIT_CURVE NID_secp160r1
#define OPENSSL_224_BIT_CURVE NID_secp224r1
#define OPENSSL_256_BIT_CURVE NID_X9_62_prime256v1

typedef struct EcGamalPk {
    EC_GROUP *group;
    BIGNUM   *order;
    EC_POINT *generator;
    EC_POINT *point;
    BIGNUM   *p, *a, *b;
} EcGamalPk;

typedef struct EcGamalKeys {
    EcGamalPk *pk;
    BIGNUM    *sk;
} EcGamalKeys;

typedef struct EcGamalCiphertext {
    EC_POINT *c1;
    EC_POINT *c2;
} EcGamalCiphertext;

int
set_ec_group (
    EcGamalPk *pk,
    int   sec_par);

int
generate_ecelgamal_keys (
    EcGamalKeys *keys,
    int       sec_par);

int
ecelgamal_add (
    EcGamalCiphertext *res,
    EcGamalCiphertext    a,
    EcGamalCiphertext    b,
    EcGamalPk           pk);

int
ecelgamal_ptmul (
    EcGamalCiphertext *res,
    EcGamalCiphertext    a,
    BIGNUM              *b,
    EcGamalPk           pk);

int
permute_ecelgamal_ciphertexts (
    EcGamalCiphertext **ctxts,
    unsigned long         len,
    EC_GROUP           *group);

#endif//_ECELGAMAL_UTILS_H_
