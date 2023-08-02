#ifndef _EC_ELGAMAL_AH_UTILS_H_
#define _EC_ELGAMAL_AH_UTILS_H_

#include "../utils.h"
#include "utils.h"


int
ec_elgamal_ah_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par);

int
ec_elgamal_brute_force_discrete_log (BIGNUM  *exponent,
				     EcGamalPk     *pk,
				     EC_POINT *element);

int
ec_elgamal_ah_decrypt (BIGNUM          *bn_plain,
		       EcGamalKeys          keys,
		       EcGamalCiphertext  cipher);

int
ec_elgamal_skip_dlog_check_is_at_infinity (EcGamalKeys         keys,
					   EcGamalCiphertext cipher);

#endif//_EC_ELGAMAL_AH_UTILS_H_
