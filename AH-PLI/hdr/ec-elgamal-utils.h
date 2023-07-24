#ifndef _EC_ELGAMAL_UTILS_H_
#define _EC_ELGAMAL_UTILS_H_

#include <openssl/bn.h> // BIGNUM
#include <openssl/ec.h> // EC_POINT
#include <openssl/obj_mac.h> // NID's
#include "../hdr/utils.h"

/* Some Curves */
/* NID_X9_62_prime192v1 */
#define OPENSSL_GROUP NID_X9_62_prime256v1

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
set_ec_group (EcGamalPk *pk,
	      int       NID);

int
generate_ec_elgamal_keys (EcGamalKeys *keys);

int
ec_elgamal_add (EcGamalCiphertext *res,
		EcGamalCiphertext    a,
		EcGamalCiphertext    b,
		EcGamalPk           pk);

int
ec_elgamal_ptmul (EcGamalCiphertext *res,
		  EcGamalCiphertext    a,
		  BIGNUM              *b,
		  EcGamalPk           pk);

#endif//_EC_ELGAMAL_UTILS_H_
