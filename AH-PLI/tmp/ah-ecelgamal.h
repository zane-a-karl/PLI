#ifndef _AH_ECELGAMAL_H_
#define _AH_ECELGAMAL_H_

#include <openssl/bn.h>
#include <inttypes.h>

#define CURVE_192_SEC NID_X9_62_prime192v1
#define CURVE_256_SEC NID_X9_62_prime256v1

struct ah_gamal_key {
    char is_public;
    EC_POINT *Y;
    BIGNUM *secret;
};

struct ah_gamal_ciphertext {
    EC_POINT *C1;
    EC_POINT *C2;
};

int
ah_gamal_encrypt (ah_gamal_ciphertext *ctxt,
		  uint64_t *plaintext,
		  ah_gamal_key *key,
		  EC_GROUP *ec_group);

#endif//_AH_ECELGAMAL_H_