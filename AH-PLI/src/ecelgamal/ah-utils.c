#include "../../hdr/ecelgamal/ah-utils.h"


int
ecelgamal_ah_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par)
{
    int r = 1;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; perror("Failed to create new ctx"); return FAILURE; }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem) { r = 0; perror("Failed to make new bn"); return FAILURE; }
    cipher->c1 = EC_POINT_new(pk->group);
    if (!cipher->c1) { r = 0; perror("Failed to make new ecpoint"); return FAILURE; }
    cipher->c2 = EC_POINT_new(pk->group);
    if (!cipher->c2) { r = 0; perror("Failed to make new ecpoint"); return FAILURE; }

    r = BN_rand_range_ex(bn_rand_elem, pk->order, sec_par, ctx);
    if (!r) { perror("Failed to gen rand elem"); return FAILURE; }

    // Set c1 = G(bn_rand_elem)
    r = EC_POINT_mul(pk->group, cipher->c1, bn_rand_elem, NULL, NULL, ctx);
    if (!r) { perror("Failed to calc G(bn_rand_elem)"); return FAILURE; }
    // Set c2 = G(msg) + (pk->point*bn_rand_elem)
    r = EC_POINT_mul(pk->group, cipher->c2, bn_plain, pk->point, bn_rand_elem, ctx);
    if (!r) { perror("Failed to calc G(m)+pt(rand)"); return FAILURE; }

    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
ecelgamal_brute_force_discrete_log (
    BIGNUM  *exponent,
    EcGamalPk     *pk,
    EC_POINT *element)
{
    /* TODO */
    return FAILURE;
}

int
ecelgamal_ah_decrypt (
    BIGNUM          *bn_plain,
    EcGamalKeys          keys,
    EcGamalCiphertext  cipher)
{
    int r = 1;
    EC_POINT *c1_x_sk;
    EC_POINT *ecpt_plain;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; perror("Failed to create new ctx"); return FAILURE; }
    c1_x_sk = EC_POINT_new(keys.pk->group);
    if (!c1_x_sk) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }
    ecpt_plain = EC_POINT_new(keys.pk->group);
    if (!ecpt_plain) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }

    // Calculate c1 * keys.sk then invert
    r = EC_POINT_mul(keys.pk->group, c1_x_sk, NULL, cipher.c1, keys.sk, ctx);
    if (!r) { perror("Failed to calc c1*sk"); return FAILURE; }
    r = EC_POINT_invert(keys.pk->group, c1_x_sk, ctx);
    if (!r) { perror("Failed to calc - (c1*sk)"); return FAILURE; }
    // Evaluate c2 - (c1*sk)
    r = EC_POINT_add(keys.pk->group, ecpt_plain, cipher.c2, c1_x_sk, ctx);
    if (!r) { perror("Failed to calc c2 - (c1*sk)"); return FAILURE; }
    // Calculate the EC Discrete log
    r = ecelgamal_brute_force_discrete_log(bn_plain, keys.pk, ecpt_plain);
    /* r = baby_step_giant_step(ecpt_plain); */
    if (!r) { perror("Failed to calculate discrete log"); return FAILURE; }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
ecelgamal_skip_dlog_check_is_at_infinity (
    EcGamalKeys         keys,
    EcGamalCiphertext cipher,
    int             *matches)
{
    int r = 1;
    EC_POINT *c1_x_sk;
    EC_POINT *ecpt_plain;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; perror("Failed to create new ctx"); return FAILURE; }
    c1_x_sk = EC_POINT_new(keys.pk->group);
    if (!c1_x_sk) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }
    ecpt_plain = EC_POINT_new(keys.pk->group);
    if (!ecpt_plain) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }

    // Calculate c1 * keys.sk then invert
    r = EC_POINT_mul(keys.pk->group, c1_x_sk, NULL, cipher.c1, keys.sk, ctx);
    if (!r) { perror("Failed to calc c1*sk"); return FAILURE; }
    r = EC_POINT_invert(keys.pk->group, c1_x_sk, ctx);
    if (!r) { perror("Failed to calc - (c1*sk)"); return FAILURE; }
    // Evaluate c2 - (c1*sk)
    r = EC_POINT_add(keys.pk->group, ecpt_plain, cipher.c2, c1_x_sk, ctx);
    if (!r) { perror("Failed to calc c2 - (c1*sk)"); return FAILURE; }
    // Compare ecpt_plain to infty
    if (EC_POINT_is_at_infinity(keys.pk->group, ecpt_plain)) {
	*matches += 1;
    }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
