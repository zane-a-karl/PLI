#include "../hdr/elgamal-utils.h"


extern int SEC_PAR;

/**
 * Reads from the file 'filename' and
 * takes the log_base2('SEC_PAR')-th bignum
 * @param output bignum from ascii hex string
 * @param filename of file to parse
 * @return SUCCESS/FAILURE
 */
int
parse_hardcoded_bignum (BIGNUM      **output,
			const char *filename)
{
    const int len = 2048;
    char *buf = calloc(len, sizeof(char));
    int c = 0;
    int r = 0;
    int i = 0;
    int sec_par_i = log_base2(SEC_PAR);
    int buf_i = 0;
    FILE *fin = fopen(filename, "r");
    if (!fin) {	return general_error("Failed to open hardcoded input file"); }

    memset(buf, 0, len);
    do {
	c = fgetc(fin);
	if (isalnum(c)) {
	    if (i == sec_par_i) {
		do {
		    buf[buf_i++] = c;
		    c = fgetc(fin);
		} while(isalnum(c));
		r = BN_hex2bn(output, buf);
		if (!r) { return openssl_error("Failed to hex2bn hardcoded bignum"); }
		break;
	    } else {
		do {
		    c = fgetc(fin);
		} while(isalnum(c));
		i++;
	    }
	}
    } while (!feof(fin) && !ferror(fin));

    free(buf);
    r = fclose(fin);
    if (r == EOF) { return general_error("Failed to close hardcoded input file"); }
    return SUCCESS;
}

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
    /* int is_safe = 1; */
    /* BIGNUM *add; */
    BN_CTX *ctx = BN_CTX_new();
    keys->pk = calloc(1, sizeof(struct GamalPk));
    keys->pk->generator = BN_new();
    keys->pk->modulus   = BN_new();
    keys->pk->mul_mask  = BN_new();
    keys->sk = calloc(1, sizeof(struct GamalSk));
    keys->sk->secret    = BN_new();
    /* add = BN_new(); */

    // Assume generator = 3
    // Doing this randomly each time takes forever
    r = BN_set_word(keys->pk->generator, 3ULL);
    if (!r) { return openssl_error("Failed to set generator"); }

    /**************Gen the field's prime modulus**************/
    /* Run openssl dhparam -text -out dhparams.pem -2 2048 */
    /* -2 means it's a safe prime */
    /* r = parse_modulus_from_dhparams_file(); */
    r = parse_hardcoded_bignum(&keys->pk->modulus, "input/primes.txt");
    /* Generates safe prime modulus on the fly */
    /* Fails for large SEC_PAR value due to low internal entropy */
    /* r = BN_set_word(add, 8ULL); */
    /* if (!r) { return openssl_error("Failed to set add"); } */
    /* r = BN_generate_prime_ex2(keys->pk->modulus, SEC_PAR, is_safe, */
    /* 			       add, keys->pk->generator, NULL, ctx); */
    /* Get prime from https://bigprimes.org/ */
    /* r = BN_set_word(keys->pk->modulus, 172758658065239ULL); */
    if (!r) { return openssl_error("Failed to generate prime ex2"); }
    // Check if it's indeed prime
    r = BN_check_prime(keys->pk->modulus, ctx, NULL);
    if (!r) { return openssl_error("Failed to generate true prime"); }

    // Gen the field element secret key
    /* This will fail for high values of SEC_PAR due to your computer having low entropy I guess */
    /* r = BN_rand_range_ex(keys->sk->secret, keys->pk->modulus, SEC_PAR, ctx); */
    /* If you need things to not fail just grab one of the hardcoded values */
    r = parse_hardcoded_bignum(&keys->sk->secret, "input/secret-keys.txt");
    if (!r) { return openssl_error("Failed to gen secret key"); }
    // Gen the field element mul_mask
    r = BN_mod_exp(keys->pk->mul_mask, keys->pk->generator,
		   keys->sk->secret, keys->pk->modulus, ctx);
    if (!r) { return openssl_error("Failed to calculate h = g^sk"); }

    /* BN_free(add); */
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
