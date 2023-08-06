#include "../../hdr/elgamal/ah-utils.h"


/**
 * Calculates the ah elgamal encryption of the bn_ptxt
 * @param the resulting ciphertext structure
 * @param the public key structure
 * @param the ptxt to be encrypted
 */
int
elgamal_ah_encrypt (
    GamalCiphertext *ciphertext,
    GamalPk                  pk,
    BIGNUM        *bn_plaintext,
    int                 sec_par)
{
    int r = 1;
    BIGNUM *bn_rand_elem;
    BIGNUM *gen_exp_ptxt;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx)            { r = 0; return openssl_error("Failed to make new ctx"); }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem)   { r = 0; return openssl_error("Failed to make new bn"); }
    gen_exp_ptxt = BN_new();
    if (!gen_exp_ptxt)   { r = 0; return openssl_error("Failed to make new bn"); }
    ciphertext->c1 = BN_new();
    if (!ciphertext->c1) { r = 0; return openssl_error("Failed to make new bn"); }
    ciphertext->c2 = BN_new();
    if (!ciphertext->c2) { r = 0; return openssl_error("Failed to make new bn"); }

    switch (sec_par) {
    case 2048:
	r = BN_rand_range_ex(bn_rand_elem, pk.modulus, 224, ctx);
	break;
    case 1024:
	r = BN_rand_range_ex(bn_rand_elem, pk.modulus, 160, ctx);
	break;
    default:
	r = BN_rand_range_ex(bn_rand_elem, pk.modulus, sec_par, ctx);
	break;
    }
    if (!r) { return openssl_error("Failed to gen rand elem"); }

    // Set c1 = generator^rand_elem
    r = BN_mod_exp(ciphertext->c1, pk.generator, bn_rand_elem, pk.modulus, ctx);
    if (!r) { return openssl_error("Failed to calc g^rand_elem"); }
    // Set c2 = g^m * mul_mask^rand_elem
    r = BN_mod_exp(gen_exp_ptxt, pk.generator, bn_plaintext, pk.modulus, ctx);
    if (!r) { return openssl_error("Failed to calc g^ptxt"); }
    if (BN_is_negative(bn_plaintext)) {
	BN_mod_inverse(gen_exp_ptxt, gen_exp_ptxt, pk.modulus, ctx);
	if (!gen_exp_ptxt) { r = 0; return openssl_error("Failed to invert gen_exp_ptxt"); }
    }
    r = BN_mod_exp(ciphertext->c2, pk.mul_mask, bn_rand_elem, pk.modulus, ctx);
    if (!r) { return openssl_error("Failed to calc h^rand_elem"); }
    r = BN_mod_mul(ciphertext->c2, gen_exp_ptxt, ciphertext->c2, pk.modulus, ctx);
    if (!r) { return openssl_error("Failed to calc g^ptxt * h^rand"); }

    BN_free(bn_rand_elem);
    BN_free(gen_exp_ptxt);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
elgamal_ah_decrypt (
    BIGNUM        *bn_plaintext,
    GamalKeys              keys,
    GamalCiphertext *ciphertext)
{
    int r = 1;
    BIGNUM *denominator;
    BIGNUM *tmp;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    denominator = BN_new();
    if (!denominator) { r = 0; return openssl_error("Failed to make new bn"); }

    // Calculate 1/c1 then 1/c1^sk
    tmp = BN_mod_inverse(denominator, ciphertext->c1, keys.pk->modulus, ctx);
    if (!tmp) { r = 0; return openssl_error("Failed to calc 1/c1"); }
    r = BN_mod_exp(denominator, denominator, keys.sk->secret, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc (1/c1)^sk"); }
    // Evaluate c2/c1^sk
    r = BN_mod_mul(bn_plaintext, ciphertext->c2, denominator, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc c2/c1^sk"); }

    // Calculate the Discrete log
    r = elgamal_brute_force_discrete_log(bn_plaintext, keys.pk, bn_plaintext);
    /* r = baby_step_giant_step(bn_plaintext); */
    if (!r) { return openssl_error("Failed to calculate discrete log"); }

    BN_free(denominator);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
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
elgamal_brute_force_discrete_log (
    BIGNUM *exponent,
    GamalPk      *pk,
    BIGNUM  *element)
{
    int r = 1;
    BIGNUM *x, *test_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    x = BN_new();
    test_elem = BN_new();
    BN_one(test_elem);
    BN_zero(x);
    do {
	if (0 == BN_cmp(test_elem, element)) {
	    exponent = BN_dup(x);
	    return SUCCESS;
	}
	r = BN_add_word(x, 1ULL);//inc here
	if (!r) { return openssl_error("Failed to increment"); }
	r = BN_mod_mul(test_elem, test_elem, pk->generator, pk->modulus, ctx);
	if (!r) { return openssl_error("Failed to calc g^x * g"); }
    } while ( BN_cmp(x, pk->modulus) < 0 );

    BN_free(x);
    BN_free(test_elem);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
baby_step_giant_step (
    BIGNUM *bn_plaintext)
{
    //TODO
    return FAILURE;
}

int
elgamal_skip_dlog_check_is_one (
    GamalKeys         keys,
    GamalCiphertext cipher,
    int           *matches)
{
    int r = 1;
    BIGNUM *denominator;
    BIGNUM *decrypt_res;
    BIGNUM *tmp;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    denominator = BN_new();
    if (!denominator) { r = 0; return openssl_error("Failed to make new bn"); }
    decrypt_res = BN_new();
    if (!decrypt_res) { r = 0; return openssl_error("Failed to make new bn"); }

    // Calculate 1/c1 then 1/c1^sk
    tmp = BN_mod_inverse(denominator, cipher.c1, keys.pk->modulus, ctx);
    if (!tmp) { r = 0; return openssl_error("Failed to calc 1/c1"); }
    r = BN_mod_exp(denominator, denominator, keys.sk->secret, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc (1/c1)^sk"); }
    // Evaluate c2/c1^sk
    r = BN_mod_mul(decrypt_res, cipher.c2, denominator, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc c2/c1^sk"); }
    if (BN_is_one(decrypt_res)) {
	*matches += 1;
    }

    BN_free(denominator);
    BN_free(decrypt_res);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
