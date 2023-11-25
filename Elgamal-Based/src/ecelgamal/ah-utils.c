#include <openssl/ec.h>                // EC_POINT
#include "../../hdr/ecelgamal/utils.h" // EcGamalCiphertext
#include "../../hdr/macros.h"          // SUCCESS
#include "../../hdr/ecelgamal/ah-utils.h"
#include "../../hdr/error/utils.h"     // openssl_error()


int
ecelgamal_ah_encrypt (
    EcGamalCiphertext *cipher,
    EcGamalPk             *pk,
    BIGNUM          *bn_plain,
    int               sec_par)
{
    int r;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem) { r = 0; return openssl_error("Failed to make new bn"); }
    cipher->c1 = EC_POINT_new(pk->group);
    if (!cipher->c1) { r = 0; return openssl_error("Failed to make new ecpoint"); }
    cipher->c2 = EC_POINT_new(pk->group);
    if (!cipher->c2) { r = 0; return openssl_error("Failed to make new ecpoint"); }

    r = BN_rand_range_ex(bn_rand_elem, pk->order, sec_par, ctx);
    if (!r) { return openssl_error("Failed to gen rand elem"); }

    // Set c1 = G(bn_rand_elem)
    r = EC_POINT_mul(pk->group, cipher->c1, bn_rand_elem, NULL, NULL, ctx);
    if (!r) { return openssl_error("Failed to calc G(bn_rand_elem)"); }
    // Set c2 = G(msg) + (pk->point*bn_rand_elem)
    r = EC_POINT_mul(pk->group, cipher->c2, bn_plain, pk->point, bn_rand_elem, ctx);
    if (!r) { return openssl_error("Failed to calc G(m)+pt(rand)"); }

    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
ecelgamal_brute_force_discrete_log (
    BIGNUM  *exponent,
    EcGamalPk     *pk,
    EC_POINT *element)
{
    /* TODO */
    return general_error("Never implemented ecelgamal_brute_froce_discrete_log()");
}

int
ecelgamal_ah_decrypt (
    BIGNUM          *bn_plain,
    EcGamalKeys          keys,
    EcGamalCiphertext  cipher)
{
    int r;
    EC_POINT *c1_x_sk;
    EC_POINT *ecpt_plain;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    c1_x_sk = EC_POINT_new(keys.pk->group);
    if (!c1_x_sk) { r = 0; return openssl_error("Failed to make new ecpt"); }
    ecpt_plain = EC_POINT_new(keys.pk->group);
    if (!ecpt_plain) { r = 0; return openssl_error("Failed to make new ecpt"); }

    // Calculate c1 * keys.sk->secret then invert
    r = EC_POINT_mul(keys.pk->group, c1_x_sk, NULL, cipher.c1, keys.sk->secret, ctx);
    if (!r) { return openssl_error("Failed to calc c1*sk"); }
    r = EC_POINT_invert(keys.pk->group, c1_x_sk, ctx);
    if (!r) { return openssl_error("Failed to calc - (c1*sk)"); }
    // Evaluate c2 - (c1*sk)
    r = EC_POINT_add(keys.pk->group, ecpt_plain, cipher.c2, c1_x_sk, ctx);
    if (!r) { return openssl_error("Failed to calc c2 - (c1*sk)"); }
    // Calculate the EC Discrete log
    r = ecelgamal_brute_force_discrete_log(bn_plain, keys.pk, ecpt_plain);
    /* r = baby_step_giant_step(ecpt_plain); */
    if (!r) { return openssl_error("Failed to calculate discrete log"); }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
ecelgamal_skip_dlog_check_is_at_infinity (
    int             *matched,
    EcGamalKeys         keys,
    EcGamalCiphertext cipher)
{
    int r;
    EC_POINT *c1_x_sk;
    EC_POINT *ecpt_plain;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; return openssl_error("Failed to create new ctx"); }
    c1_x_sk = EC_POINT_new(keys.pk->group);
    if (!c1_x_sk) { r = 0; return openssl_error("Failed to make new ecpt"); }
    ecpt_plain = EC_POINT_new(keys.pk->group);
    if (!ecpt_plain) { r = 0; return openssl_error("Failed to make new ecpt"); }

    // Calculate c1 * keys.sk->secret then invert
    r = EC_POINT_mul(keys.pk->group, c1_x_sk, NULL, cipher.c1, keys.sk->secret, ctx);
    if (!r) { return openssl_error("Failed to calc c1*sk"); }
    r = EC_POINT_invert(keys.pk->group, c1_x_sk, ctx);
    if (!r) { return openssl_error("Failed to calc - (c1*sk)"); }
    // Evaluate c2 - (c1*sk)
    r = EC_POINT_add(keys.pk->group, ecpt_plain, cipher.c2, c1_x_sk, ctx);
    if (!r) { return openssl_error("Failed to calc c2 - (c1*sk)"); }
    // Compare ecpt_plain to infty
    if (EC_POINT_is_at_infinity(keys.pk->group, ecpt_plain)) {
	*matched = 1;
    } else {
	*matched = 0;
    }

    EC_POINT_free(c1_x_sk);
    EC_POINT_free(ecpt_plain);
    BN_CTX_free(ctx);
    return SUCCESS;
}
