#include "../hdr/mh-elgamal.h"

int
mh_elgamal_encrypt (GamalCiphertext *ciphertext,
		    GamalPk                 *pk,
		    BIGNUM        *bn_plaintext)
{
    int r;
    unsigned int sec_par;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem) {
	perror("Failed to make new bn");
	return FAILURE;
    }
    ciphertext->c1 = BN_new();
    if (!ciphertext->c1) {
	perror("Failed to make new bn");
	return FAILURE;
    }
    ciphertext->c2 = BN_new();
    if (!ciphertext->c2) {
	perror("Failed to make new bn");
	return FAILURE;
    }
    sec_par = 49;

    r = BN_rand_range_ex(bn_rand_elem, pk->modulus,
			 sec_par, ctx);
    if (!r) {
	perror("Failed to gen rand elem");
	return FAILURE;
    }

    // Set c1 = generator^rand_elem
    r = BN_mod_exp(ciphertext->c1, pk->generator,
		   bn_rand_elem, pk->modulus, ctx);
    if (!r) {
	perror("Failed to calc g^rand_elem");
	return FAILURE;
    }
    // Set c2 = m * mul_mask^rand_elem
    r = BN_mod_exp(ciphertext->c2, pk->mul_mask,
		   bn_rand_elem, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc h^rand_elem");
	return FAILURE;
    }
    r = BN_mod_mul(ciphertext->c2, bn_plaintext,
		   ciphertext->c2, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc ptxt * h^rand");
	return FAILURE;
    }

    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
mh_elgamal_decrypt (BIGNUM        *bn_plaintext,
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

    BN_free(denominator);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
mh_skip_decrypt_check_equality (GamalKeys             *keys,
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

    // Calculate c1^sk
    r = BN_mod_exp(denominator, ciphertext->c1,
		   keys->sk->secret,
		   keys->pk->modulus, ctx);
    if (!r) {
	perror("Failed to calc c1^sk");
	return FAILURE;
    }

    if (BN_cmp(denominator, ciphertext->c2) == 0) {
	    printf("Found a match!\n");
    } else {
	    printf("Not a match.\n");
    }

    BN_free(denominator);
    BN_CTX_free(ctx);
    return SUCCESS;
}
