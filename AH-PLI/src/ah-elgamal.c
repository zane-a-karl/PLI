#include "../hdr/ah-elgamal.h"

int
ah_elgamal_encrypt (GamalCiphertext *ciphertext,
		    GamalPk                 *pk,
		    BIGNUM        *bn_plaintext)
{
    int r;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }

    bn_rand_elem   = BN_new();
    ciphertext->c1 = BN_new();
    ciphertext->c2 = BN_new();

    r = BN_rand_range(bn_rand_elem, pk->modulus);
    if (!r) {
	perror("Failed to gen rand elem");
	return FAILURE;
    }

    // Set c1
    r = BN_mod_exp(ciphertext->c1, pk->generator,
		   bn_rand_elem, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc g^rand");
	return FAILURE;
    }
    // Set c2
    r = BN_mod_exp(ciphertext->c2, pk->mul_mask,
		   bn_rand_elem, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc h^rand");
	return FAILURE;
    }
    r = BN_mod_exp(bn_plaintext, pk->generator,
		   bn_plaintext, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc g^ptxt");
	return FAILURE;
    }
    r = BN_mod_mul(ciphertext->c2, bn_plaintext,
		   ciphertext->c2, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc g^ptxt * h^rand");
	return FAILURE;
    }
    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
ah_elgamal_decrypt (BIGNUM        *bn_plaintext,
		    GamalKeys             *keys,
		    GamalCiphertext *ciphertext)
{
    int r;
    BIGNUM *denominator;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }
    denominator = BN_new();
    if (!denominator) {
	perror("Failed to make new bn");
	return FAILURE;
    }

    // Calculate 1/c1 then 1/c1^sk
    if (!BN_mod_inverse(denominator,
			ciphertext->c1,
			keys->pk->modulus,
			ctx)) {
	perror("Failed to calc 1/c1");
	return FAILURE;
    }
    r = BN_mod_exp(denominator, denominator,
		   keys->sk->secret,
		   keys->pk->modulus, ctx);
    if (!r) {
	perror("Failed to calc (1/c1)^sk");
	return FAILURE;
    }
    // evaluate c2/c1^sk
    r = BN_mod_mul(bn_plaintext, ciphertext->c2,
		   denominator,
		   keys->pk->modulus, ctx);
    if (!r) {
	perror("Failed to calc c2/c1^sk");
	return FAILURE;
    }

    //Calculate the Discrete log
    r = brute_force_discrete_log(bn_plaintext,
				 keys->pk,
				 bn_plaintext);
    /* r = baby_step_giant_step(bn_plaintext); */
    if (!r) {
	perror("Failed to calculate discrete log");
	return FAILURE;
    }

    BN_free(denominator);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Calculate 'x' which satisfies g^x = elem
 * @param exponent output
 * @param el gamal public key input
 * @param element input
 * @return SUCCESS/FAILURE
 */
int
brute_force_discrete_log(BIGNUM *exponent,
			 GamalPk      *pk,
			 BIGNUM  *element)
{
    int r;
    BIGNUM *x, *test_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }
    x = BN_new();
    test_elem = BN_new();
    BN_one(test_elem);
    BN_zero(x);
    do {
	if (0 == BN_cmp(test_elem, element)) {
	    exponent = BN_dup(x);
	    /* printf("yes!\n"); */
	    return SUCCESS;
	} /* else { */
	/*     printf("no!!\n");	     */
	/*     break; */
	/* } */
	r = BN_add_word(x, 1ULL);//inc here
	if (!r) {
	    perror("Failed to increment");
	    return FAILURE;
	}
	r = BN_mod_mul(test_elem, test_elem,
		       pk->generator, pk->modulus,
		       ctx);
	if (!r) {
	    perror("Failed to calc g^x * g");
	    return FAILURE;
	}
    } while ( BN_cmp(x, pk->modulus) < 0 );

    BN_free(x);
    BN_free(test_elem);
    BN_CTX_free(ctx);
    return FAILURE;
}

int
baby_step_giant_step(BIGNUM *bn_plaintext)
{
    //TODO
    return FAILURE;
}
