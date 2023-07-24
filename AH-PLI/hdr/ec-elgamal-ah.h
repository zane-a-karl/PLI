#ifndef _EC_ELGAMAL_AH_H_
#define _EC_ELGAMAL_AH_H_

#include "../hdr/utils.h"
#include "../hdr/ec-elgamal-utils.h"


int
ah_ec_elgamal_encrypt (EcGamalCiphertext *cipher,
		       EcGamalPk             *pk,
		       BIGNUM          *bn_plain);

int
ec_elgamal_brute_force_discrete_log (BIGNUM  *exponent,
				     EcGamalPk     *pk,
				     EC_POINT *element);

int
ah_ec_elgamal_decrypt (BIGNUM          *bn_plain,
		       EcGamalKeys          keys,
		       EcGamalCiphertext  cipher);

int
ec_elgamal_skip_dlog_check_is_at_infinity (EcGamalKeys         keys,
					   EcGamalCiphertext cipher);

#endif//_EC_ELGAMAL_AH_H_
