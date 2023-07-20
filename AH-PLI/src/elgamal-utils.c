#include "../hdr/elgamal-utils.h"


extern int SEC_PAR;

/**
 * allocs space for and initializes fields in
 * GamalKeys structure
 * @param structure to hold the keys
 * @return SUCCESS/FAILURE
 */
int
generate_elgamal_keys (GamalKeys *keys)
{
    int r;
    int is_safe = 1;
    BIGNUM *add;
    BN_CTX *ctx = BN_CTX_new();
    keys->pk = calloc(1, sizeof(struct GamalPk));
    keys->pk->generator = BN_new();
    keys->pk->modulus   = BN_new();
    keys->pk->mul_mask  = BN_new();
    keys->sk = calloc(1, sizeof(struct GamalSk));
    keys->sk->secret    = BN_new();
    add = BN_new();

    // Assume generator = 3
    // Doing this randomly each time takes forever
    r = BN_set_word(keys->pk->generator, 3ULL);
    if (!r) { return openssl_error("Failed to set generator"); }

    // Gen the field's prime modulus
    // Run openssl dhparam -text -out dhparams.pem -2 2048
    // -2 means it's a safe prime
    /* r = parse_modulus_from_dhparams_file(); */
    r = BN_set_word(add, 8ULL);
    if (!r) { return openssl_error("Failed to set add"); }
    r = BN_generate_prime_ex2(keys->pk->modulus, SEC_PAR, is_safe,
			       add, keys->pk->generator, NULL, ctx);
    /* Get prime from https://bigprimes.org/ */
    /* r = BN_set_word(keys->pk->modulus, 172758658065239ULL); */
    if (!r) { return openssl_error("Failed to generate prime ex2"); }
    // Check if it's indeed prime
    r = BN_check_prime(keys->pk->modulus, ctx, NULL);
    if (!r) { return openssl_error("Failed to generate true prime"); }

    // Gen the field element secret key
    // This will fail for high values of SEC_PAR due to your computer having low entropy I guess
    r = BN_rand_range_ex(keys->sk->secret, keys->pk->modulus, SEC_PAR, ctx);
    if (!r) { return openssl_error("Failed to gen secret key"); }
    // Gen the field element mul_mask
    r = BN_mod_exp(keys->pk->mul_mask, keys->pk->generator,
		    keys->sk->secret, keys->pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calculate h = g^sk"); }

    BN_free(add);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 * Computes res = a*b = (a.c1*b.c1, a.c2*b.c2)
 * @param resulting output
 * @param a input
 * @param b input
 * @return SUCCESS/FAILURE
 */
int
elgamal_mul (GamalCiphertext *res,
	     GamalCiphertext    a,
	     GamalCiphertext    b,
	     BIGNUM      *modulus)
{
    int r = 1;
    BN_CTX *ctx = BN_CTX_new();
    res->c1 = BN_new();
    if (!res->c1) { r = 0; return openssl_error("Error allocating res->c1"); }
    res->c2 = BN_new();
    if (!res->c2) { r = 0; return openssl_error("Error allocating res->c2"); }
    // Calc a.c1 * b.c1
    r = BN_mod_mul(res->c1, a.c1, b.c1, modulus, ctx);
    if (!r) { return openssl_error("Error calculating a.c1 * b.c1"); }
    // Calc a.c2 * b.c2
    r = BN_mod_mul(res->c2, a.c2, b.c2, modulus, ctx);
    if (!r) { return openssl_error("Error calculating a.c2 * b.c2"); }

    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 * Computes res = a^r = (a.c1^r, a.c2^r)
 * @param resulting output
 * @param a input
 * @param exponent input
 * @return SUCCESS/FAILURE
 */
int
elgamal_exp (GamalCiphertext *res,
	     GamalCiphertext    a,
	     BIGNUM     *exponent,
	     BIGNUM      *modulus)
{
    int r = 1;
    BN_CTX *ctx = BN_CTX_new();
    res->c1 = BN_new();
    if (!res->c1) { r = 0; return openssl_error("Error allocating res->c1"); }
    res->c2 = BN_new();
    if (!res->c2) { r = 0; return openssl_error("Error allocating res->c2"); }
    // Calc a.c1^r
    r = BN_mod_exp(res->c1, a.c1, exponent, modulus, ctx);
    if (!r) { return openssl_error("Error calculating a.c1^r"); }
    // Calc a.c2^r
    r = BN_mod_exp(res->c2, a.c2, exponent, modulus, ctx);
    if (!r) { return openssl_error("Error calculating a.c2^r"); }

    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
elgamal_skip_decrypt_check_equality (GamalKeys             keys,
				     GamalCiphertext cipher)
{
    int r = 1;
    BIGNUM *denominator;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r= 0; return openssl_error("Failed to create new ctx"); }
    denominator = BN_new();
    if (!denominator) { r = 0; return openssl_error("Failed to make new bn"); }
    // Calculate c1^sk
    r = BN_mod_exp(denominator, cipher.c1, keys.sk->secret, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc c1^sk"); }

    if (BN_cmp(denominator, cipher.c2) == 0) {
	printf("Found a match!\n");
    } else {
	printf("Not a match.\n");
    }

    BN_free(denominator);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
elgamal_skip_dlog_check_is_one (GamalKeys             keys,
				GamalCiphertext cipher)
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
    // evaluate c2/c1^sk
    r = BN_mod_mul(decrypt_res, cipher.c2, denominator, keys.pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calc c2/c1^sk"); }
    r = BN_print_fp(stdout, decrypt_res);
    if (BN_is_one(decrypt_res)) {
	printf(" -> Found a match!\n");
    } else {
	printf(" -> Not a match.\n");
    }

    BN_free(denominator);
    BN_free(decrypt_res);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
