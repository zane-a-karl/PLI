#ifndef _MH_ELGAMAL_H_
#define _MH_ELGAMAL_H_

#include "../hdr/elgamal-utils.h"


int
mh_elgamal_encrypt (GamalCiphertext *ciphertext,
		    GamalPk                 *pk,
		    BIGNUM        *bn_plaintext);

int
mh_elgamal_decrypt (BIGNUM        *bn_plaintext,
		    GamalKeys             *keys,
		    GamalCiphertext *ciphertext);

#endif//_MH_ELGAMAL_H_
