#ifndef _AH_ELGAMAL_H_
#define _AH_ELGAMAL_H_

#include "../hdr/elgamal-utils.h"


int
ah_elgamal_encrypt (GamalCiphertext *ciphertext,
		    GamalPk                 *pk,
		    BIGNUM        *bn_plaintext);

int
ah_elgamal_decrypt (BIGNUM        *bn_plaintext,
		    GamalKeys             *keys,
		    GamalCiphertext *ciphertext);

int
brute_force_discrete_log(BIGNUM *exponent,
			 GamalPk      *pk,
			 BIGNUM  *element);

int
baby_step_giant_step(BIGNUM *bn_plaintext);

int
ah_skip_dlog_check_is_one (GamalKeys             *keys,
			   GamalCiphertext *ciphertext);

#endif//_AH_ELGAMAL_H_
