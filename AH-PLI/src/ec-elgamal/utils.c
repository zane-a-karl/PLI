#include "../../hdr/ec-elgamal/utils.h"


/**
 * @param pk is the public key
 * @param NID is the numerical identifier of the
 * curve/group specified by openssl/obj_mac.h
 */
int
set_ec_group (
    EcGamalPk *pk,
    int       NID)
{
    pk->group = EC_GROUP_new_by_curve_name(NID);
    if (!pk->group) { perror("Failed to set pk group to nid"); return FAILURE; }
    return SUCCESS;
}

/**
 * allocs space for and initializes fields in
 * GamalKeys structure
 * @param structure to hold the keys
 * @return SUCCESS/FAILURE
 */
int
generate_ec_elgamal_keys (
    EcGamalKeys *keys,
    int       sec_par)
{
    int r;
    const EC_POINT *g;
    BN_CTX *ctx = BN_CTX_new();

    // Initialize pk->group
    keys->pk = calloc(1, sizeof(EcGamalPk));
    r = set_ec_group(keys->pk, OPENSSL_GROUP);
    if (!r) { perror("Failed to set ec group"); return FAILURE; }
    // Initialize pk->order
    keys->pk->order = BN_new();
    r = EC_GROUP_get_order(keys->pk->group, keys->pk->order, ctx);
    if (!r) { perror("Failed to get group order"); return FAILURE; }
    // Initialize sk
    keys->sk = BN_new();
    if (!keys->sk) { r = 0; perror("Failed to alloc keys->sk"); return FAILURE; }
    r = BN_rand_range_ex(keys->sk, keys->pk->order, sec_par, ctx);
    if (!r) { perror("Failed to generate random sk"); return FAILURE; }
    g = EC_GROUP_get0_generator(keys->pk->group);
    keys->pk->generator = EC_POINT_dup(g, keys->pk->group);
    if (!keys->pk->generator) { r = 0; perror("Failed to get generator"); return FAILURE; }
    // Initialize pk->point
    keys->pk->point = EC_POINT_new(keys->pk->group);
    if (!keys->pk->point) { r = 0; perror("Failed to alloc pk point"); return FAILURE; }
    // calc point = G(sk) + 0*0
    r = EC_POINT_mul(keys->pk->group, keys->pk->point, keys->sk, NULL, NULL, ctx);
    if (!keys->pk->point) { r = 0; perror("Failed to get pk point"); return FAILURE; }
    // Initialize curve params p, a, and b
    keys->pk->p = BN_new();
    keys->pk->a = BN_new();
    keys->pk->b = BN_new();
    r = EC_GROUP_get_curve(keys->pk->group, keys->pk->p, keys->pk->a, keys->pk->b, ctx);
    if (!r) { perror("Failed to get curve params"); return FAILURE; }
    printf("p = ");
    BN_print_fp(stdout, keys->pk->p);
    printf("\n");
    printf("a = ");
    BN_print_fp(stdout, keys->pk->a);
    printf("\n");
    printf("b = ");
    BN_print_fp(stdout, keys->pk->b);
    printf("\n");    
    // Check if it's indeed prime
    r = BN_check_prime(keys->pk->p, ctx, NULL);
    if (!r) { perror("Failed to generate true prime"); return FAILURE; }

    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
ec_elgamal_add (
    EcGamalCiphertext *res,
    EcGamalCiphertext    a,
    EcGamalCiphertext    b,
    EcGamalPk           pk)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    res->c1 = EC_POINT_new(pk.group);
    if (!res->c1) { r = 0; return openssl_error("Error allocating res->c1"); }
    res->c2 = EC_POINT_new(pk.group);
    if (!res->c2) { r = 0; return openssl_error("Error allocating res->c2"); }
    // Calc a.c1 + b.c1
    r = EC_POINT_add(pk.group, res->c1, a.c1, b.c1, ctx);
    if (!r) { perror("Failed to add c1 terms"); return FAILURE; }
    // Calc a.c2 + b.c2
    r = EC_POINT_add(pk.group, res->c2, a.c2, b.c2, ctx);
    if (!r) { perror("Failed to add c2 terms"); return FAILURE; }

    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
ec_elgamal_ptmul (
    EcGamalCiphertext *res,
    EcGamalCiphertext    a,
    BIGNUM              *b,
    EcGamalPk           pk)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    res->c1 = EC_POINT_new(pk.group);
    if (!res->c1) { r = 0; return openssl_error("Error allocating res->c1"); }
    res->c2 = EC_POINT_new(pk.group);
    if (!res->c2) { r = 0; return openssl_error("Error allocating res->c2"); }
    // Calc a.c1 * b
    r = EC_POINT_mul(pk.group, res->c1, NULL, a.c1, b, ctx);
    if (!r) { perror("Failed to ptmul c1 terms"); return FAILURE; }
    // Calc a.c2 * b
    r = EC_POINT_mul(pk.group, res->c2, NULL, a.c2, b, ctx);
    if (!r) { perror("Failed to ptmul c2 terms"); return FAILURE; }

    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
