#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/input-args/utils.h" // enum MessageType
#include "../../hdr/macros.h"           // SUCCESS 
#include <math.h>                       // floor()
**********************************************************/

int
hash (
    unsigned char **output,
    void            *input,
    char    *hash_alg_name,
    size_t hash_digest_len,
    enum MessageType  type,
    ...);

int
symmetric_encrypt (
    unsigned char **output,
    size_t     *output_len,
    void            *input,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType  type);

int
symmetric_decrypt (
    unsigned char **output,
    unsigned char   *input,
    int          input_len,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType  type);

int
evaluate_polynomial_at(
    BIGNUM   **share,
    BIGNUM *coeffs[],
    int        input,
    int    threshold,
    BIGNUM  *modulus);

int
construct_shamir_shares (
    BIGNUM **shares,
    BIGNUM  *secret,
    BIGNUM *modulus,
    InputArgs    ia);

int
try_reconstruct_with (
    BIGNUM **secret,
    BIGNUM      **x,    
    BIGNUM      **y,
    int      length,
    BIGNUM *modulus);

int
reconstruct_shamir_secret (
    BIGNUM         **secret,
    BIGNUM         **shares,
    size_t        threshold,
    size_t subset_indexes[],
    BIGNUM         *modulus);

int
iteratively_check_all_subsets (
    size_t              *matches,
    unsigned char *secret_digest,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus);

int
check_remaining_shares_against_poly (
    size_t              *matches,
    unsigned char *secret_digest,
    size_t       *subset_indexes,
    BIGNUM             *shares[],
    InputArgs                 ia,    
    BIGNUM              *modulus);

void
print_mat (
    BIGNUM *mat[],
    size_t      r,
    size_t      c);

int
setup_BW_matrix (
    BIGNUM      *mat[],
    BIGNUM   *shares[],
    BIGNUM *eval_pts[],
    BIGNUM    *modulus,
    size_t           n,
    size_t           e);

int
swap_rows (
    BIGNUM  **mat,
    size_t    dst,
    size_t    src,
    size_t n_cols);

/* I was basically there but this link helped me see that the inverse needed to be recaclulated
 each time after the row in question was completed
https://stackoverflow.com/questions/31756413/solving-a-simple-matrix-in-row-reduced-form-in-c*/
int
gaussian_elim (
    BIGNUM     *mat[],
    BIGNUM   *modulus,
    size_t      nrows,
    size_t      ncols);

int
parse_QE_from_BW_mat (
    BIGNUM      *Q[],
    BIGNUM      *E[],
    BIGNUM *BW_mat[],
    size_t         n,
    size_t         e);

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
    BIGNUM    *modulus);

int
exec_BW_alg (
    size_t              *matches,
    unsigned char *secret_digest,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus);

#endif//CRYPTO_UTILS_H
