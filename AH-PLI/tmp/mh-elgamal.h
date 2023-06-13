#ifndef _MH_ELGAMAL_H_
#define _MH_ELGAMAL_H_

#include "elgamal_utils.h"

int
mh_elgamal_encrypt (GamalCiphertext ciphertext,
		    GamalKeys keys,
		    uint64_t *plaintext);

int
mh_elgamal_decrypt (uint64_t *plaintext,
		    GamalKeys *keys,
		    GamalCiphertext *ciphertext);

#endif//_MH_ELGAMAL_H_