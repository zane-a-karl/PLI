#include "mh-elgamal.c"

int
mh_elgamal_encrypt (GamalCiphertext *ciphertext,
		    GamalPk *pk,
		    uint64_t *plaintext)
{
    int r;
    BIGNUM *bn_plaintext;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }

    bn_plaintext = BN_new();
    bn_rand_elem = BN_new();

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
    r = BN_set_word(bn_plaintext, plaintext);
    if (!r) {
	perror("Failed to set ptxt2bn");
	return FAILURE;
    }
    r = BN_mod_exp(ciphertext->c2, pk->mul_mask,
		   bn_rand_elem, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc h^rand");
	return FAILURE;
    }
    r = BN_mod_mul(ciphertext->c2, bn_plaintext,
		   ciphertext->c2, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc ptxt * h^rand");
	return FAILURE;
    }
    BN_free(bn_plaintext);
    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
mh_elgamal_decrypt (uint64_t *plaintext,
		    GamalKeys *keys,
		    GamalCiphertext *ciphertext)
{
    int r;
    BIGNUM *bn_plaintext;
    BIGNUM *bn_inv;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
	perror("Failed to create new ctx");
	return FAILURE;
    }

    bn_plaintext = BN_new();
    bn_inv = BN_new();

    // Calculate 1/c1^sk
    r = BN_mod_exp(bn_plaintext, ciphertext->c1,
		   keys->sk->secret,
		   keys->pk->modulus, ctx);
    if (!r) {
	perror("Failed to calc c1^sk");
	return FAILURE;
    }
    if (!BN_mod_inverse(bn_plaintext,
			bn_plaintext,
			keys->pk->modulus,
			ctx)) {
	perror("Failed to calc 1/c1^sk");
	return FAILURE;
    }
    // evaluate c2/c1^sk
    r = BN_mod_mul(bn_plaintext, ciphertext->c2,
		   bn_plaintext, pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calc c2/c1^sk");
	return FAILURE;
    }
    plaintext = BN_get_word(bn_plaintext);
    if ( plaintext + 1 < 0 ) {
	perror("Failed bn_plaintext2int");
	return FAILURE;
    }
    BN_free(bn_plaintext);
    BN_free(bn_inv);
    BN_CTX_free(ctx);
    return SUCCESS;
}