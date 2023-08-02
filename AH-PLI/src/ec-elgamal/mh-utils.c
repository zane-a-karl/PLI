#include "../../hdr/ec-elgamal/mh-utils.h"


int
mh_ec_elgamal_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par)
{
    int r = 1;
    BIGNUM *bn_rand_elem;
    BIGNUM *y_coord;
    BIGNUM *x3;
    BIGNUM *ax;
    BIGNUM *three = NULL;
    BIGNUM *one = NULL;
    EC_POINT *ecpt_plain;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx)            { r = 0; perror("Failed to create new ctx"); return FAILURE; }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem)   { r = 0; perror("Failed to make new bn"); return FAILURE; }
    y_coord = BN_new();
    if (!y_coord)        { r = 0; perror("Failed to make new bn"); return FAILURE; }
    x3 = BN_new();
    if (!x3)             { r = 0; perror("Failed to make new bn"); return FAILURE; }
    ax = BN_new();
    if (!ax)             { r = 0; perror("Failed to make new bn"); return FAILURE; }
    three = BN_new();
    if (!three)          { r = 0; perror("Failed to make new bn"); return FAILURE; }
    one = BN_new();
    if (!one)            { r = 0; perror("Failed to make new bn"); return FAILURE; }
    cipher->c1 = EC_POINT_new(pk->group);
    if (!cipher->c1) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }
    cipher->c2 = EC_POINT_new(pk->group);
    if (!cipher->c2) { r = 0; perror("Failed to make new ecpt"); return FAILURE; }

    // Map plaintext to curve
    // curve equation defined at https://www.openssl.org/docs/man3.1/man3/EC_GROUP_get_curve.html
    // y^2 = x^3 + ax + b
    r = BN_set_word(three, 3ULL);
    if (!r)    { perror("Failed to set 3"); return FAILURE; }
    r = BN_mod_exp(x3, bn_plain, three, pk->p, ctx);
    if (!r)    { perror("Failed to calc x^3"); return FAILURE; }
    r = BN_mod_mul(ax, pk->a, bn_plain, pk->p, ctx);
    if (!r)    { perror("Failed to calc a*x"); return FAILURE; }
    r = BN_mod_add(y_coord, x3, ax, pk->p, ctx);
    if (!r)    { perror("Failed to calc x^3 + a*x"); return FAILURE; }
    r = BN_mod_add(y_coord, y_coord, pk->b, pk->p, ctx);
    if (!r)    { perror("Failed to calc x^3 + a*x + b"); return FAILURE; }
    BIGNUM *bn_r = BN_mod_sqrt(y_coord, y_coord, pk->p, ctx);
    if (!bn_r) { perror("Failed to calc y^(1/2)"); return FAILURE; }
    ecpt_plain = EC_POINT_new(pk->group);
    r = EC_POINT_set_affine_coordinates(pk->group, ecpt_plain, bn_plain, y_coord, ctx);
    if (!r)    { perror("Failed to set ptxt curve coords"); return FAILURE; }
    r = EC_POINT_is_on_curve(pk->group, ecpt_plain, ctx);
    if (!r)    { perror("Failed to map ptxt to curve"); return FAILURE; }

    // Gen random subgroup element
    r = BN_rand_range_ex(bn_rand_elem, pk->order, sec_par, ctx);
    if (!r) { perror("Failed to gen rand elem"); return FAILURE; }
    // Set c1 = G(bn_rand_elem)
    r = EC_POINT_mul(pk->group, cipher->c1, bn_rand_elem, NULL, NULL, ctx);
    if (!r) { perror("Failed to calc G(rand)"); return FAILURE; }
    // Set c2 = ecpt_msg + (pk->pt*rand)
    r = EC_POINT_mul(pk->group, cipher->c2, NULL, pk->point, bn_rand_elem, ctx);
    if (!r) { perror("Failed to calc pkpt(rand)"); return FAILURE; }
    r = EC_POINT_add(pk->group, cipher->c2, ecpt_plain, cipher->c2, ctx);
    if (!r) { perror("Failed to calc ecpt_m+pt(rand)"); return FAILURE; }

    BN_free(bn_rand_elem);
    BN_free(y_coord);
    BN_free(x3);
    BN_free(ax);
    BN_free(three);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
mh_ec_elgamal_decrypt (
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
    // Recover x-coord of ecpt to get ptxt
    r = EC_POINT_get_affine_coordinates(keys.pk->group, ecpt_plain, bn_plain, NULL, ctx);
    if (!r) { perror("Failed to recover ptxt"); return FAILURE; }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
ec_elgamal_skip_decrypt_check_equality (
    EcGamalKeys       keys,
    EcGamalCiphertext cipher)
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

    // Calculate c1 * sk
    r = EC_POINT_mul(keys.pk->group, c1_x_sk, NULL, cipher.c1, keys.sk, ctx);
    if (!r) { perror("Failed to calc c1*sk"); return FAILURE; }
    // Compare c2 and (c1*sk)
    if (EC_POINT_cmp(keys.pk->group, cipher.c2, c1_x_sk, ctx) == 0) {
	printf("Found a match!\n");
    } else {
	printf("Not a match.\n");
    }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
