#include "../hdr/elgamal-utils.h"

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
    int prime_sec_par = 1024;
    unsigned int rand_sec_par = 1024;
    //a safe prime is a prime p s.t. (p-1)/2
    //is also prime, required for ElGamal sec
    int is_safe = 1;
    BN_CTX *ctx = BN_CTX_new();
    keys->pk->modulus   = BN_new();
    keys->pk->generator = BN_new();
    keys->pk->mul_mask  = BN_new();
    keys->sk->secret    = BN_new();

    // Gen the field's prime modulus
    r = BN_generate_prime_ex2(keys->pk->modulus,
			      prime_sec_par,
			      is_safe,
			      keys->pk->generator,
			      NULL, NULL, ctx);
    if (!r) {
	perror("Failed to generate prime ex2");
	return FAILURE;
    }
    // Check if it's indeed prime
    r = BN_check_prime(keys->pk->modulus,
		       ctx, NULL);
    if (!r) {
	perror("Failed to generate true prime");
	return FAILURE;
    }
    // Gen the field element secret key
    r = BN_rand_range_ex(keys->sk->secret,
			 keys->pk->modulus,
			 rand_sec_par,
			 ctx);
    if (!r) {
	perror("Failed to gen secret key");
	return FAILURE;
    }
    // Gen the field element mul_mask
    r = BN_mod_exp(keys->pk->mul_mask,
		   keys->pk->generator,
		   keys->sk->secret,
		   keys->pk->modulus,
		   ctx);
    if (!r) {
	perror("Failed to calculate h = g^x");
	return FAILURE;
    }

    BN_CTX_free(ctx);
    return SUCCESS;

}

int
alloc_gamal_pk_mem(GamalPk *pk)
{
    BN_CTX *ctx = BN_CTX_new();
    pk->modulus = BN_new();
    pk->generator = BN_new();
    pk->mul_mask = BN_new();
    if (!pk->modulus) {
	perror("Failed modulus bn new");
	return FAILURE;
    }
    if (!pk->generator) {
	perror("Failed generator bn new");
	return FAILURE;
    }
    if (!pk->mul_mask) {
	perror("Failed mulmask bn new");
	return FAILURE;
    }
    BN_CTX_free(ctx);
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
	     GamalCiphertext   *a,
	     GamalCiphertext   *b,
	     BIGNUM      *modulus)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();
    res->c1 = BN_new();
    if (!res->c1) {
	perror("Error allocating res->c1");
	return FAILURE;
    }
    res->c2 = BN_new();
    if (!res->c2) {
	perror("Error allocating res->c2");
	return FAILURE;
    }
    // Calc a.c1 * b.c1
    r = BN_mod_mul(res->c1, a->c1, b->c1,
		   modulus, ctx);
    if (!r) {
	perror("Error calculating a.c1 * b.c1");
	return FAILURE;
    }
    // Calc a.c2 * b.c2
    r = BN_mod_mul(res->c2, a->c2, b->c2,
		   modulus, ctx);
    if (!r) {
	perror("Error calculating a.c2 * b.c2");
	return FAILURE;
    }
    BN_CTX_free(ctx);
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
	     GamalCiphertext   *a,
	     BIGNUM     *exponent,
	     BIGNUM      *modulus)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();
    res->c1 = BN_new();
    if (!res->c1) {
	perror("Error allocating res->c1");
	return FAILURE;
    }
    res->c2 = BN_new();
    if (!res->c2) {
	perror("Error allocating res->c2");
	return FAILURE;
    }
    // Calc a.c1^r
    r = BN_mod_exp(res->c1, a->c1, exponent,
		   modulus, ctx);
    if (!r) {
	perror("Error calculating a.c1^r");
	return FAILURE;
    }
    // Calc a.c2^r
    r = BN_mod_mul(res->c2, a->c2, exponent,
		   modulus, ctx);
    if (!r) {
	perror("Error calculating a.c2^r");
	return FAILURE;
    }
    BN_CTX_free(ctx);
    return SUCCESS;
}