#ifndef _ELGAMAL_MH_H_
#define _ELGAMAL_MH_H_

#include "../hdr/elgamal-utils.h"


int
mh_elgamal_encrypt (GamalCiphertext *cipher,
		    GamalPk              pk,
		    BIGNUM    *bn_plaintext);

int
mh_elgamal_decrypt (BIGNUM    *bn_plaintext,
		    GamalKeys          keys,
		    GamalCiphertext  cipher);

int
elgamal_skip_decrypt_check_equality (GamalKeys         keys,
				     GamalCiphertext cipher);

#endif//_ELGAMAL_MH_H_
