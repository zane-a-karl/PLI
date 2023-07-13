#ifndef _EC_ELGAMAL_MH_H_
#define _EC_ELGAMAL_MH_H_

#include "../hdr/utils.h"
#include "../hdr/ec-elgamal-utils.h"


int
mh_ec_elgamal_encrypt (EcGamalCiphertext *cipher,
		       EcGamalPk             *pk,
		       BIGNUM          *bn_plain);

int
mh_ec_elgamal_decrypt (BIGNUM          *bn_plain,
		       EcGamalKeys          keys,
		       EcGamalCiphertext  cipher);

#endif//_EC_ELGAMAL_MH_H_
