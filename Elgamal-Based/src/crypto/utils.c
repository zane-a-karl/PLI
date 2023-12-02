#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/input-args/utils.h" // enum MessageType
#include "../../hdr/macros.h"           // SUCCESS
#include <math.h>                       // floor()
#include "../../hdr/crypto/utils.h"
#include "../../hdr/error/utils.h" // openssl_error()
#include <openssl/evp.h>	   // EVP_MD_CTX_fetch
#include <openssl/sha.h>	   // SHA_DIGEST_LENGTH


/**
 * Hashes an input into an output via the alg specified by the name given by
 * $openssl list -digest-algorithms
 */
int
hash (
    unsigned char **output,
    void            *input,
    char    *hash_alg_name,
    size_t hash_digest_len,
    enum MessageType mtype,
    ...)
{
    int r;
    size_t data_len = 0;
    unsigned char *data;
    unsigned int output_len;
    va_list args_ptr;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_MD *hash_alg = EVP_MD_fetch(NULL, hash_alg_name, NULL);
    if (!hash_alg) { return openssl_error("Failed to fetch hash_alg"); }
    r = EVP_DigestInit_ex(ctx, hash_alg, NULL);
    if (!r) { return openssl_error("Failed to init hash_alg"); }

    /* Parse 'void *input' into 'unsigned char *data' */
    switch (mtype) {
    case Bignum:
	data_len = BN_num_bytes((BIGNUM *)input);
	data = calloc(data_len, sizeof(*data));
	r = BN_bn2bin((BIGNUM *)input, data);
	if (!r) { return openssl_error("Failed to bn2bin input"); }
	break;
    case Ecpoint:
	va_start(args_ptr, mtype);
	EC_GROUP *group = va_arg(args_ptr, EC_GROUP *);
	/* Calling this fn with NULL in the output argument buf gives us the length */
	data_len = EC_POINT_point2oct(group, (EC_POINT *)input,
				      POINT_CONVERSION_UNCOMPRESSED,
				      NULL, 0, NULL);
	data = calloc(data_len, sizeof(*data));
	data_len = EC_POINT_point2oct(group, (EC_POINT *)input,
				      POINT_CONVERSION_UNCOMPRESSED,
				      data, data_len, NULL);
	va_end(args_ptr);
	if (data_len == 0) { return openssl_error("Failed to point2oct input"); }
	break;
    default:
	break;
    }

    r = EVP_DigestUpdate(ctx, data, data_len); /* strlen((char *)data)); */
    if (!r) { return openssl_error("Failed to hash data"); }

    *output = calloc(hash_digest_len, sizeof(unsigned char));
    r = EVP_DigestFinal_ex(ctx, *output, &output_len);
    if (!r) { return openssl_error("Failed to hash leftover data"); }

    // Print the hash value
    /* printf("Hash Output: "); */
    /* for (unsigned int i = 0; i < output_len; i++) { */
    /*     printf("%02x", (*output)[i]); */
    /* } */
    /* printf("\n"); */

    free(data);
    EVP_MD_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Encrypts an input into an output via the alg specified by the name given by
 * $openssl list -cipher-algorithms
 */
int
symmetric_encrypt (
    unsigned char **output,
    size_t     *output_len,
    void            *input,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType mtype)
{
    int r;
    int data_len;
    unsigned char *data;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_CIPHER *se_alg = EVP_CIPHER_fetch(NULL, se_alg_name, NULL);
    if (!se_alg) { return openssl_error("Failed to fetch se_alg"); }
    r = EVP_EncryptInit(ctx, se_alg, key, iv);
    if (!r) { return openssl_error("Failed to init se_alg"); }

    /* Parse 'void *input' into 'unsigned char *data' */
    switch (mtype) {
    case Bignum:
	data_len = EVP_MAX_MD_SIZE;
	data = calloc(data_len, sizeof(*data));
	r = BN_bn2bin((BIGNUM *)input, data);
	if (!r) { return openssl_error("Failed to bn2bin input"); }
	break;
    default:
	return openssl_error("Input unknown message typename");
	break;
    }

    *output_len = 0;
    *output = calloc(MAX_MSG_LEN, sizeof(unsigned char));
    r = EVP_EncryptUpdate(ctx, *output, &len, data, strlen((char *)data));
    if (!r) { return openssl_error("Failed to encrypt plaintext data"); }
    *output_len += len;

    r = EVP_EncryptFinal_ex(ctx, *output + *output_len, &len);
    if (!r) { return openssl_error("Failed to encrypt leftovers"); }
    *output_len += len;

    // Print ciphertext
    /* printf("Ciphertext: "); */
    /* for (int i = 0; i < *output_len; i++) */
    /*     printf("%02x ", (*output)[i]); */
    /* printf("\n"); */

    free(data);
    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Decrypts an input into an output via the alg specified by the name given by
 * $openssl list -cipher-algorithms
 */
int
symmetric_decrypt (
    unsigned char **output,
    unsigned char   *input,
    int          input_len,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType mtype)
{
    int r;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_CIPHER *se_alg = EVP_CIPHER_fetch(NULL, se_alg_name, NULL);
    if (!se_alg) { return openssl_error("Failed to fetch se_alg"); }
    r = EVP_DecryptInit(ctx, se_alg, key, iv);
    if (!r) { return openssl_error("Failed to init se_alg_name"); }

    int decryptedtext_len = 0;
    *output = calloc(MAX_MSG_LEN, sizeof(unsigned char));
    r = EVP_DecryptUpdate(ctx, *output, &len, input, input_len);
    if (!r) { return openssl_error("Failed to decrypt ctxt data"); }
    decryptedtext_len += len;

    r = EVP_DecryptFinal_ex(ctx, *output + decryptedtext_len, &len);
    if (!r) { return openssl_error("Failed to decrypt leftovers"); }
    decryptedtext_len += len;

    /* printf("Encrypted Text: "); */
    /* for (int i = 0; i < input_len; i++) */
    /*     printf("%02x ", input[i]); */
    /* printf("\n"); */

    // Add null terminator and print decrypted text
    (*output)[decryptedtext_len] = '\0';
    /* printf("Decrypted Text: "); */
    /* for (int i = 0; i < decryptedtext_len; i++) */
    /*     printf("%02x ", (*output)[i]); */
    /* printf("\n"); */

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}

/**
 *
 */
int
evaluate_polynomial_at(
    BIGNUM   **share,
    BIGNUM *coeffs[],
    int        input,
    int    threshold,
    BIGNUM  *modulus)
{
    int r;
    BIGNUM *x;
    BN_CTX *ctx = BN_CTX_new();
    x = BN_new();
    r = BN_set_word(x, (unsigned long)input);
    if (!r) { return openssl_error("Failed to initialize input x"); }
    *share = BN_dup(coeffs[threshold-1]);
    if (!(*share)) { return openssl_error("Failed to alloc share"); }
    /* Stop before 0 so prevent undef behav */
    for (int i = threshold - 1; i > 0; i--) {
	r = BN_mod_mul(*share, *share, x, modulus, ctx);
	if (!r) {return openssl_error("Failed share * x"); }
	r = BN_mod_add(*share, *share, coeffs[i - 1], modulus, ctx);
	if (!r) {return openssl_error("Failed share + coeffs[i - 1]"); }
    }
    BN_free(x);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Generates 'n'='num_shares' shares of 'secret' using a (t, n)-SSS Scheme ('t'='threshold').
 * Shares are created as poly(1..n+1)
 * @param Output array to hold shares
 * @param Secret to share
 * @param threshold
 * @param number of shares
 * @param group order
 */
int
construct_shamir_shares (
    BIGNUM **shares,
    BIGNUM  *secret,
    BIGNUM *modulus,
    InputArgs    ia)
{
    int r;
    BIGNUM *coeffs[ia.threshold];
    BN_CTX *ctx = BN_CTX_new();

    coeffs[0] = BN_dup(secret);
    printf("Secret = "); BN_print_fp(stdout, secret); printf("\n");
    for (int i = 1; i < ia.threshold; i++) {
	coeffs[i] = BN_new();
	if (!coeffs[i]) { return openssl_error("Failed to alloc coeffs"); }
	r = BN_rand_range_ex(coeffs[i], modulus, ia.secpar, ctx);
	if (!r) { return openssl_error("Failed to gen random coefficients"); }
    }
    for (int i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's shares[i] */
	r = evaluate_polynomial_at(&shares[i], coeffs, i + 1, ia.threshold, modulus);
	if (!r) { return general_error("Failed evaluate_polynomial_at i+1"); }
    }

    BN_CTX_free(ctx);
    return SUCCESS;
}

int
try_reconstruct_with (
    BIGNUM **secret,
    BIGNUM      **x,
    BIGNUM      **y,
    int      length,
    BIGNUM *modulus)
{
    int r;
    BIGNUM *sum_accum;
    BIGNUM *mul_accum;
    BIGNUM *tmp;
    BN_CTX *ctx = BN_CTX_new();
    sum_accum = BN_new();
    mul_accum = BN_new();
    tmp = BN_new();
    BN_zero(sum_accum);
    for (int i = 0; i < length; i++) {
	BN_one(mul_accum);
	for (int j = 0; j < length; j++) {
	    if (i == j) {
		continue;
	    }
	    r = BN_mod_sub(tmp, x[j], x[i], modulus, ctx);
	    BN_mod_inverse(tmp, tmp, modulus, ctx);
	    r = BN_mod_mul(tmp, x[j], tmp, modulus, ctx);
	    r = BN_mod_mul(mul_accum, mul_accum, tmp, modulus, ctx);
	}
	r = BN_mod_mul(mul_accum, y[i], mul_accum, modulus, ctx);
	r = BN_mod_add(sum_accum, sum_accum, mul_accum, modulus, ctx);
    }
    if (!r) { return openssl_error("An error occurred be more specific"); }
    (*secret) = BN_dup(sum_accum);
    if (!(*secret)) { return openssl_error("Failed to dup sum_accum"); }

    BN_free(sum_accum);
    BN_free(mul_accum);
    BN_free(tmp);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 * @param
 * @param the attempted reconstructed secret
 * @param the shares given
 * @param the threshold
 * @param the number of shares
 * @param an array containing the indexes of the nCt combination of shares we are trying
 * @param the field order
 */
int
reconstruct_shamir_secret (
    BIGNUM         **secret,
    BIGNUM         **shares,
    size_t        threshold,
    size_t subset_indexes[],
    BIGNUM         *modulus)
{
    int r;
    size_t t = threshold;
    size_t i;
    BIGNUM *save_x[threshold];
    BIGNUM *save_y[threshold];
    BN_CTX *ctx = BN_CTX_new();

    for (i = 0; i < t; i++) {
	save_x[i] = BN_new();
	save_y[i] = BN_new();
	BN_set_word(save_x[i], subset_indexes[i] + 1);
	BN_copy(save_y[i], shares[subset_indexes[i]]);
    }
    /* for (i = 0; i < t; i++) { */
    /* 	printf("x = "); BN_print_fp(stdout, save_x[i]); */
    /* 	printf(", y = "); BN_print_fp(stdout, save_y[i]); printf("\n"); */
    /* } */
    /* Fn alloc's secret */
    r = try_reconstruct_with(secret, save_x, save_y, t, modulus);
    if (!r) { return openssl_error("Failed during try_reconstruct_with"); }
    for (i = 0; i < t; i++) {
	BN_free(save_x[i]);
	BN_free(save_y[i]);
    }
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 *
 */
int
iteratively_check_all_subsets (
    size_t              *matches,
    unsigned char *secret_digest,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus)
{
    int r;
    const size_t n = ia.num_entries;
    const size_t t = ia.threshold;
    /* Array to store indices of selected elements */
    size_t subset_indexes[t];

    /* Initialize the first subset as [0, 1, 2, ..., t-1] */
    for (size_t i = 0; i < t; i++) {
        subset_indexes[i] = i;
    }

    /* START: Check the current subset for validity */
    BIGNUM *possible_secret;
    unsigned char *possible_secret_digest;
    size_t digest_len;
    while (subset_indexes[0] < n - t + 1) {

	/* for (size_t i = 0; i < t; i++) { */
	/*     printf((i == t-1 ? "%zu:\n" : "%zu, "), subset_indexes[i]); */
	/* } */
	/* Fn alloc's possible_secret */
	r = reconstruct_shamir_secret(&possible_secret, shares, t, subset_indexes, modulus);
	if (!r) { return general_error("Failed to reconstruct shamir secret"); }
	switch (ia.secpar) {
	case 160: /* Fall Through */
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's possible_secret_digest */
	    r = hash(&possible_secret_digest, possible_secret, "SHA1", digest_len, Bignum);
	    break;
	case 224: /* Fall Through */
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash poissble_secret"); }
	/* printf("------------------\n"); */
	/* for (size_t j = 0; j < digest_len; j++) */
	/*     printf("%02x ", secret_digest[j]); */
	/* printf("\n"); */
	/* for (size_t j = 0; j < digest_len; j++) */
	/*     printf("%02x ", possible_secret_digest[j]); */
	/* printf("\n\n\n"); */
	if (0 == memcmp(secret_digest, possible_secret_digest, digest_len)) {
	    for (size_t j = 0; j < t; j++) {
		matches[subset_indexes[j]] = 1;
	    }
	    /* You've found a match, now check the other shares against the polynomial */
	    r = check_remaining_shares_against_poly(matches, secret_digest, subset_indexes,
						    shares, ia, modulus);
	    if (!r) { return general_error("Failed during check_remaining_shares_against_poly"); }
	    BN_free(possible_secret);
	    free(possible_secret_digest);
	    break;
	}
	BN_free(possible_secret);
	free(possible_secret_digest);
	/* END: Check the current subset viability */

        /* Generate the next subset */
        ssize_t i = t - 1;
        while (i >= 0 && subset_indexes[i] == i + n - t) {
            i--;
        }

	/* All subsets generated */
        if (i < 0) {
            break;
        }

        subset_indexes[i]++;

        /* Update the rest of the indices */
        for (size_t j = i + 1; j < t; j++) {
            subset_indexes[j] = subset_indexes[j - 1] + 1;
        }
    }
    return SUCCESS;
}

int
check_remaining_shares_against_poly (
    size_t              *matches,
    unsigned char *secret_digest,
    size_t       *subset_indexes,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus)
{
    int r;
    BIGNUM *possible_secret;
    unsigned char *possible_secret_digest;
    size_t digest_len;
    size_t n = ia.num_entries;
    size_t t = ia.threshold;
    /* 1. Try with other indexes after final in 'subset_indexes' */
    for (size_t i = subset_indexes[t-1] + 1; i < n; i++) {
	subset_indexes[t-1] = i;
	/* Fn alloc's possible_secret */
	r = reconstruct_shamir_secret(&possible_secret, shares, t, subset_indexes, modulus);
	if (!r) { return general_error("Failed to reconstruct shamir secret"); }
	switch (ia.secpar) {
	case 160:		/* Fall through */
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's possible_secret_digest */
	    r = hash(&possible_secret_digest, possible_secret, "SHA1", digest_len, Bignum);
	    break;
	case 224:		/* Fall through */	    
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash poissble_secret"); }
	if (0 == memcmp(secret_digest, possible_secret_digest, digest_len)) {
	    matches[subset_indexes[t-1]] = 1;
	}
	BN_free(possible_secret);
	free(possible_secret_digest);
    }
    return SUCCESS;
}

void
print_mat (
    BIGNUM *mat[],
    size_t      r,
    size_t      c)
{
    for (size_t i = 0; i < r; i++) {
	for (size_t j = 0; j < c; j++) {
	    BN_print_fp(stdout, mat[c*i + j]);
	    printf((j == c-1) ? "\n" : ", ");
	}
    }
}

int
setup_BW_matrix (
    BIGNUM      *mat[],
    BIGNUM   *shares[],
    BIGNUM *eval_pts[],
    BIGNUM    *modulus,
    size_t           n,
    size_t           e)
{
    int rv;
    size_t i;
    size_t j;
    size_t r;
    size_t c;
    BIGNUM *exp;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    r = n;
    c = n + 1;
    exp = BN_new();
    if (!exp) { return openssl_error("Failed to alloc exp"); }
    for (i = 0; i < r; i++) {
	for (j = 0; j < c; j++) {
	    mat[c*i + j] = BN_new();
	    if (!mat[c*i + j]) { return openssl_error("Failed to alloc mat"); }
	}
    }

    /* Zeroth column */
    for (i = 0, j = 0; i < r; i++) {
	BN_copy(mat[c*i + j], shares[i]);
	if (!mat[c*i + j]) { return openssl_error("Failed to copy shares to mat"); }
    }
    /* E polynomial columns */
    for (i = 0; i < r; i++) {
	for (j = 1; j < e; j++) {
	    rv = BN_set_word(exp, (unsigned long)(j));
	    if (!rv) { return openssl_error("Failed to set exp to j"); }
	    rv = BN_mod_exp(mat[c*i + j], eval_pts[i], exp, modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod exp eval_pts"); }
	    rv = BN_mod_mul(mat[c*i + j], shares[i], mat[c*i + j], modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod mul shares and mat"); }
	}
    }

    /* Q polynomial columns */
    for (i = 0, j = e; i < r; i++) {
	rv = BN_one(mat[c*i + j]);
	if (!rv) { return openssl_error("Failed to set mat to 1"); }
	/* Equivalent to (-mat[i][j] % modulus) */
	rv = BN_mod_sub(mat[c*i + j], modulus, mat[c*i + j], modulus, ctx);
	if (!rv) { return openssl_error("Failed to mod sub mod and mat"); }
    }
    for (i = 0; i < r; i++) {
	for (j = e + 1; j < c - 1; j++) {
	    rv = BN_set_word(exp, (unsigned long)(j - e));
	    if (!rv) { return openssl_error("Failed to set exp"); }
	    rv = BN_mod_exp(mat[c*i + j], eval_pts[i], exp, modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod exp eval_pts and exp"); }
	    rv = BN_mod_sub(mat[c*i + j], modulus, mat[c*i + j], modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod sub mod and mat"); }
	}
    }

    /* Augmented column */
    for (i = 0, j = c - 1; i < r; i++) {
	rv = BN_set_word(exp, (unsigned long)(e));
	if (!rv) { return openssl_error("Failed to set exp"); }
	rv = BN_mod_exp(mat[c*i + j], eval_pts[i], exp, modulus, ctx);
	if (!rv) { return openssl_error("Failed to mod exp eval_pts and exp"); }
	rv = BN_mod_mul(mat[c*i + j], shares[i], mat[c*i + j], modulus, ctx);
	if (!rv) { return openssl_error("Failed to mod mul shares and mat"); }
	rv = BN_mod_sub(mat[c*i + j], modulus, mat[c*i + j], modulus, ctx);
	if (!rv) { return openssl_error("Failed to mod sub mod and mat"); }
    }
    BN_free(exp);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/** Swaps src with dst
 */
int
swap_rows (
    BIGNUM  **mat,
    size_t    dst,
    size_t    src,
    size_t n_cols)
{
    size_t c;
    BIGNUM *tmp;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    tmp = BN_new();
    if (!tmp) { return openssl_error("Failed to alloc tmp"); }
    c = n_cols;

    for (size_t j = 0; j < c; j++) {
	BN_copy(tmp, mat[c*src + j]);
	if (!tmp) { return openssl_error("Failed to copy mat to tmp"); }
	BN_copy(mat[c*src + j], mat[c*dst + j]);
	if (!mat[c*src + j]) { return openssl_error("Failed to copy mat to mat"); }
	BN_copy(mat[c*dst + j], tmp);
	if (!mat[c*dst + j]) { return openssl_error("Failed to copy tmp to mat"); }
    }

    BN_free(tmp);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/* I was basically there but this link helped me see that the inverse needed to be recaclulated
 each time after the row in question was completed
https://stackoverflow.com/questions/31756413/solving-a-simple-matrix-in-row-reduced-form-in-c*/
int
gaussian_elim (
    BIGNUM     *mat[],
    BIGNUM   *modulus,
    size_t      nrows,
    size_t      ncols)
{
    int rv;
    size_t r;
    size_t c;
    BIGNUM *inv;
    BIGNUM *fac;
    BIGNUM *tmp;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    inv = BN_new();
    if (!inv) { return openssl_error("Failed to alloc inv"); }
    fac = BN_new();
    if (!fac) { return openssl_error("Failed to alloc fac"); }
    tmp = BN_new();
    if (!tmp) { return openssl_error("Failed to alloc tmp"); }
    r = nrows;
    c = ncols;

    for (size_t pivot = 0; pivot < r; pivot++) {
	/* printf("pivot = %zu\n", pivot); */
	if (BN_is_zero(mat[c*pivot + pivot])) {
	    for (size_t k = pivot + 1; k < r; k++) {
		if (!BN_is_zero(mat[c*k + pivot])) {
		    rv = swap_rows(mat, pivot, k, c);
		    if (!rv) { return general_error("Failed during swap_rows"); }
		    break;
		}
	    }
	}

	for (size_t i = 0; i < r; i++) {
	    /* printf("mat[pivot][pivot] = "); */
	    /* BN_print_fp(stdout, mat[c*pivot + pivot]); printf("\n"); */
	    /* We don't want to fail here, we want to break and move on to the next iteration
	       rows being linearly DEpendent means we move on decreasing the errors */
	    if (BN_is_zero(mat[c*pivot + pivot])) {
		break;
	    }
	    inv = BN_mod_inverse(inv, mat[c*pivot + pivot], modulus, ctx);
	    if (!inv) { return openssl_error("Failed to invert mat"); }
	    rv = BN_mod_mul(fac, mat[c*i + pivot], inv, modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod mul mat and inv"); }

	    for (size_t j = 0; j < c; j++) {
		if (pivot == i) {
		    rv = BN_mod_mul(mat[c*i + j], mat[c*i + j], inv, modulus, ctx);
		    if (!rv) { return openssl_error("Failed to mod mul mat and inv"); }
		} else {
		    rv = BN_mod_mul(tmp, mat[c*pivot + j], fac, modulus, ctx);
		    if (!rv) { return openssl_error("Failed to mod mul mat and fac"); }
		    rv = BN_mod_sub(mat[c*i + j], mat[c*i + j], tmp, modulus, ctx);
		    if (!rv) { return openssl_error("Failed to mod mul mat and tmp"); }
		}
	    }
	}
	/* printf("-----------------------\n"); */
	/* print_mat(mat, r, c); */
    }
    BN_free(inv);
    BN_free(tmp);
    BN_free(fac);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
parse_QE_from_BW_mat (
    BIGNUM      *Q[],
    BIGNUM      *E[],
    BIGNUM *BW_mat[],
    size_t         n,
    size_t         e)
{
    int rv;
    size_t c;
    size_t r;
    size_t q;

    r = n;
    c = n + 1;
    q = n - e - 1;
    for (size_t i = 0; i < e + 1; i++) {
	E[i] = BN_new();
	if (!E[i]) { return openssl_error("Failed to alloc E"); }
    }
    for (size_t i = 0; i < q + 1; i++) {
	Q[i] = BN_new();
	if (!Q[i]) { return openssl_error("Failed to alloc Q"); }
    }
    rv = BN_one(E[e]);
    if (!rv) { return openssl_error("Failed to set e^e to 1"); }
    for (size_t i = 0; i < r; i ++) {
	if (i < e) {
	    BN_copy(E[i], BW_mat[c*i + c - 1]);
	    if (!E[i]) { return openssl_error("Failed to copy BW_mat to E"); }
	} else if (e <= i) {
	    BN_copy(Q[i - e], BW_mat[c*i + c - 1]);
	    if (!Q[i - e]) { return openssl_error("Failed to copy BW_mat to Q"); }
	}
    }
    return SUCCESS;
}

/**
 * Fn assumes that a_deg > b_deg, it is the caller's
 * duty to check that a_deg > b_deg before calling.
 */
int
polynomial_divide (
    BIGNUM *poly_quo[],
    BIGNUM   *poly_a[],
    BIGNUM   *poly_b[],
    size_t       a_deg,
    size_t       b_deg,
    BIGNUM    *modulus)
{
    if (a_deg < b_deg) { return FAILURE; }
    int rv;
    size_t a;
    size_t b;
    size_t q;
    size_t quo_deg;
    const size_t rem_len = a_deg + 1;
    BIGNUM *poly_rem[rem_len];
    BIGNUM *inv;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc BN_CTX"); }
    inv = BN_new();
    if (!inv) { return openssl_error("Failed to alloc inv"); }
    quo_deg = a_deg - b_deg;
    for (size_t i = 0; i < quo_deg + 1; i++) {
	poly_quo[i] = BN_new();
	if (!poly_quo[i]) { return openssl_error("Failed to alloc poly_quo[i]"); }
    }
    for (size_t i = 0; i < a_deg + 1; i++) {
	poly_rem[i] = BN_new();
	if (!poly_rem[i]) { return openssl_error("Failed to alloc poly_rem[i]"); }
    }

    for (size_t i = 0; i < a_deg + 1 - b_deg; i++) {
	q = quo_deg - i;
	for (size_t j = 0; j < b_deg + 1; j++) {
	    a = a_deg - i - j;
	    b = b_deg - j;

	    if (j == 0) {
		BN_mod_inverse(inv, poly_b[b], modulus, ctx);
		rv = BN_mod_mul(poly_quo[q], poly_a[a], inv, modulus, ctx);
		if (!rv) { return openssl_error("Failed to mod mul poly_a and inv"); }
	    }
	    rv = BN_mod_mul(poly_rem[a], poly_quo[q], poly_b[b], modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod mul poly_quo and poly_b"); }
	    rv = BN_mod_sub(poly_rem[a], poly_a[a], poly_rem[a], modulus, ctx);
	    if (!rv) { return openssl_error("Failed to mod mul poly_a and poly_rem"); }
	    BN_copy(poly_a[a], poly_rem[a]);
	    if (!poly_a[a]) { return FAILURE; }
	}
	/* for (ssize_t j = a_deg - i; j >= 0; j--) { */
	/*     BN_copy(poly_a[j], poly_rem[j]); */
	/*     if (!poly_a[j]) { return openssl_error("Failed to BN_copy poly_a and poly_rem"); } */
	/*     /\* TODO: Check for non-zero remainder? *\/ */
	/*     BN_zero(poly_rem[j]); */
	/* } */
    }

    for (size_t i = 0; i < a_deg + 1; i++) {
	BN_free(poly_rem[i]);
    }
    BN_free(inv);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
exec_BW_alg (
    size_t              *matches,
    unsigned char *secret_digest,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus)
{
    int rv;
    size_t r;
    size_t c;
    ssize_t e;
    size_t succeeded;
    ssize_t sum_pivots;
    double max_errors;
    BIGNUM *possible_secret = NULL;
    const size_t n = ia.num_entries;
    const size_t t = ia.threshold;
    BIGNUM *BW_mat[n][n + 1];
    BIGNUM *eval_pts[n];

    for (size_t i = 0 ; i < n; i++) {
	eval_pts[i] = BN_new();
	if (!eval_pts[i]) { return openssl_error("Failed to alloc eval_pts[i]"); }
	rv = BN_set_word(eval_pts[i], (unsigned long)(i + 1));
	if (!rv) { return openssl_error("Failed to set_word on eval_pts[i]"); }
    }

    r = n;
    c = n + 1;
    succeeded = 1;
    sum_pivots = 0;
    max_errors = floor((double)(n - t) / (double)2);

    for (e = max_errors; e >= 0; e--) {
	printf("################################\n");
	printf("assumed errors iteration = %zu\n", e);
	printf("################################\n\n\n");
	/* Fn alloc's each BW_mat[c*i + j] */
	rv = setup_BW_matrix(&BW_mat[0][0], shares, eval_pts, modulus, n, e);
	if (!rv) { return general_error("Failed during setup_BW_matrix"); }
	rv = gaussian_elim(&BW_mat[0][0], modulus, r, c);
	if (!rv) { return general_error("Failed during gaussian_elim"); }
	/* printf("------------\n"); */
	/* print_mat(&BW_mat[0][0], r, c); */
	for (size_t i = 0; i < r; i++) {
	    if (BN_is_one(BW_mat[i][i])) {
		sum_pivots++;
	    }
	}
	if (sum_pivots == r) {
	    succeeded = 1;
	    break;
	}
	sum_pivots = 0;
    }
    if (succeeded) {
	printf("Successfully reconstructed\n");
	const size_t w = e + 1; // deg = e
	const size_t v = n - e; // deg = n-e-1
	const size_t q = n - e - 1;
	BIGNUM *E[w];
	BIGNUM *Q[v];
	/* Fn alloc's E and Q */
	rv = parse_QE_from_BW_mat(Q, E, &BW_mat[0][0], n, e);
	if (!rv) { return general_error("Failed during parse_QE_from_BW_mat"); }
	const size_t f = q - e + 1; // deg = q-e
	BIGNUM *F[f];
	/* Fn alloc's F */
	rv = polynomial_divide(F, Q, E, q, e, modulus);
	if (!rv) { return general_error("Failed during polynomial_divide"); }
	/* print_mat(F, 1, f); */
	printf("Possible secret = "); BN_print_fp(stdout, F[0]); printf("\n");
	unsigned char *possible_secret_digest;
	size_t digest_len;
	switch (ia.secpar) {
	case 160: /* Fall Through */
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's possible_secret_digest */
	    rv = hash(&possible_secret_digest, F[0], "SHA1", digest_len, Bignum);
	    break;
	case 224: /* Fall Through */
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    rv = hash(&possible_secret_digest, F[0], "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    rv = hash(&possible_secret_digest, F[0], "SHA256", digest_len, Bignum);
	    break;
	}
	if (0 == memcmp(secret_digest, possible_secret_digest, digest_len)) {
	    printf("The digests match!!!!!\n");
	    /* BN_free(possible_secret); */
	    for (size_t i = 0; i < n; i++) {
		/* Using possible_secret as a tmp storage var */
		/* Fn alloc's possible_secret */
		rv = evaluate_polynomial_at(&possible_secret, E, i + 1, w, modulus);
		if (!rv) { return general_error("Failed evaluate_polynomial_at i+1"); }
		if (!BN_is_zero(possible_secret)) {
		    matches[i] = 1;
		}
		BN_free(possible_secret);
	    }
	} else {
	    printf("Match failed in spite of reconstruction\n");
	}
	for (size_t i = 0; i < e + 1; i++) {
	    BN_free(E[i]);
	}
	for (size_t i = 0; i < q + 1; i++) {
	    BN_free(Q[i]);
	}
    } else {
	printf("Failed to reconstruct\n");
	/* print_mat(&BW_mat[0][0], r, c); */
    }
    /* possible_secret freed above! */
    /* BN_free(possible_secret); */
    for (size_t i = 0 ; i < n; i++) {
	BN_free(eval_pts[i]);
    }
    return SUCCESS;
}
