#include "../../hdr/ecelgamal/utils.h"


/**
 * @param pk is the public key
 * @param NID is the numerical identifier of the
 * curve/group specified by openssl/obj_mac.h
 */
int
set_ec_group (
    EcGamalPk *pk,
    int   sec_par)
{
    switch (sec_par) {
    case 160:
	pk->group = EC_GROUP_new_by_curve_name(OPENSSL_160_BIT_CURVE);
	break;
    case 224:
	pk->group = EC_GROUP_new_by_curve_name(OPENSSL_224_BIT_CURVE);
	break;
    default:
	pk->group = EC_GROUP_new_by_curve_name(OPENSSL_256_BIT_CURVE);
	break;
    }
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
ecelgamal_generate_keys (
    EcGamalKeys *keys,
    int       sec_par)
{
    int r;
    const EC_POINT *g;
    BN_CTX *ctx = BN_CTX_new();

    // Initialize pk->group
    keys->pk = calloc(1, sizeof(EcGamalPk));
    r = set_ec_group(keys->pk, sec_par);
    if (!r) { perror("Failed to set ec group"); return FAILURE; }
    // Initialize pk->order
    keys->pk->order = BN_new();
    r = EC_GROUP_get_order(keys->pk->group, keys->pk->order, ctx);
    if (!r) { perror("Failed to get group order"); return FAILURE; }
    /* printf("order = "); */
    /* BN_print_fp(stdout, keys->pk->order); */
    /* printf("\n"); */
    // Initialize sk
    keys->sk = calloc(1, sizeof(EcGamalPk));    
    keys->sk->secret = BN_new();
    if (!keys->sk->secret) { r = 0; perror("Failed to alloc keys->sk->secret"); return FAILURE; }
    r = BN_rand_range_ex(keys->sk->secret, keys->pk->order, sec_par, ctx);
    if (!r) { perror("Failed to generate random sk"); return FAILURE; }
    g = EC_GROUP_get0_generator(keys->pk->group);
    keys->pk->generator = EC_POINT_dup(g, keys->pk->group);
    if (!keys->pk->generator) { r = 0; perror("Failed to get generator"); return FAILURE; }
    // Initialize pk->point
    keys->pk->point = EC_POINT_new(keys->pk->group);
    if (!keys->pk->point) { r = 0; perror("Failed to alloc pk point"); return FAILURE; }
    // calc point = G(sk) + 0*0
    r = EC_POINT_mul(keys->pk->group, keys->pk->point, keys->sk->secret, NULL, NULL, ctx);
    if (!keys->pk->point) { r = 0; perror("Failed to get pk point"); return FAILURE; }
    // Initialize curve params p, a, and b
    keys->pk->p = BN_new();
    keys->pk->a = BN_new();
    keys->pk->b = BN_new();
    r = EC_GROUP_get_curve(keys->pk->group, keys->pk->p, keys->pk->a, keys->pk->b, ctx);
    if (!r) { perror("Failed to get curve params"); return FAILURE; }
    /* printf("p = "); */
    /* BN_print_fp(stdout, keys->pk->p); */
    /* printf("\n"); */
    /* printf("a = "); */
    /* BN_print_fp(stdout, keys->pk->a); */
    /* printf("\n"); */
    /* printf("b = "); */
    /* BN_print_fp(stdout, keys->pk->b); */
    /* printf("\n"); */
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
ecelgamal_add (
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
ecelgamal_ptmul (
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

int
ecelgamal_permute_ciphertexts (
    EcGamalCiphertext *ciphers,
    unsigned long          len,
    EC_GROUP            *group)
{
    int r;
    unsigned long rand;
    EC_POINT *bn_tmp_c1;
    EC_POINT *bn_tmp_c2;
    BIGNUM *bn_len;
    BIGNUM *bn_rand;
    BN_CTX *ctx = BN_CTX_new();
    bn_tmp_c1 = EC_POINT_new(group);
    bn_tmp_c2 = EC_POINT_new(group);
    bn_len = BN_new();
    bn_rand = BN_new();

    r = BN_set_word(bn_len, len);
    for (int i = 0; i < len; i++) {
	r = BN_rand_range(bn_rand, bn_len);
	if (!r) {return openssl_error("Failed bn_rand_range()"); }
	rand = BN_get_word(bn_rand);
	EC_POINT_copy(bn_tmp_c1, ciphers[i].c1);
	EC_POINT_copy(bn_tmp_c2, ciphers[i].c2);

	EC_POINT_copy(ciphers[i].c1, ciphers[rand].c1);
	EC_POINT_copy(ciphers[i].c2, ciphers[rand].c2);

	EC_POINT_copy(ciphers[rand].c1, bn_tmp_c1);
	EC_POINT_copy(ciphers[rand].c2, bn_tmp_c2);
    }
    EC_POINT_free(bn_tmp_c1);
    EC_POINT_free(bn_tmp_c2);
    BN_free(bn_len);
    BN_free(bn_rand);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
ecelgamal_send_pk (
    int        sockfd,
    EcGamalPk     *pk,
    char *conf_prefix)
{
    int r;
    int nid;
    /* printf("%s\n", conf_prefix); */
    nid = EC_GROUP_get_curve_name(pk->group);
    r = send_msg(sockfd, &nid, "\t- NID group =", Integer);
    if (!r) { return general_error("Failed to send NID group"); }
    r = send_msg(sockfd, pk->order, "\t- order =", Bignum);
    if (!r) { return general_error("Failed to send order"); }
    r = send_msg(sockfd, pk->generator, "\t- generator =", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to send generator"); }
    r = send_msg(sockfd, pk->point, "\t- point  =", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to send point"); }

    return SUCCESS;
}

int
ecelgamal_send_ciphertext (
    int           sockfd,
    EcGamalCiphertext *c,
    EcGamalPk        *pk,
    char    *conf_prefix)
{
    int r;
    /* printf("%s\n", conf_prefix); */
    r = send_msg(sockfd, c->c1, "\t- c1 = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to send ciphertext.c1"); }
    r = send_msg(sockfd, c->c2, "\t- c2 = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to send ciphertext.c2"); }
    return SUCCESS;
}

int
ecelgamal_recv_pk (
    int        sockfd,
    EcGamalPk     *pk,
    char *conf_prefix)
{
    int r;
    int nid = 0;
    BN_CTX *ctx = BN_CTX_new();

    r = recv_msg(sockfd, &nid, "group nid   = ", Integer);
    if (!r) { return general_error("Failed to recv server pk group"); }
    pk->group = EC_GROUP_new_by_curve_name(nid);
    if (!pk->group) {r = 0; return openssl_error("Failed to alloc group");}

    pk->generator = EC_POINT_new(pk->group);
    if (!pk->generator) {r = 0; return openssl_error("Failed to alloc generator");}
    pk->order = BN_new();
    if (!pk->order) {r = 0; return openssl_error("Failed to alloc order");}
    pk->point = EC_POINT_new(pk->group);
    if (!pk->point) {r = 0; return openssl_error("Failed to alloc point");}
    pk->p = BN_new();
    if (!pk->p) {r = 0; return openssl_error("Failed to alloc p");}
    pk->a = BN_new();
    if (!pk->a) {r = 0; return openssl_error("Failed to alloc a");}
    pk->b = BN_new();
    if (!pk->b) {r = 0; return openssl_error("Failed to alloc b");}

    r = recv_msg(sockfd, &pk->order, "order   = ", Bignum);
    if (!r) { return general_error("Failed to recv server pk order"); }
    r = recv_msg(sockfd, &pk->generator, "generator   = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to recv server pk generator"); }
    r = recv_msg(sockfd, &pk->point, "point   = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to recv server pk point"); }
    r = EC_GROUP_get_curve(pk->group, pk->p, pk->a, pk->b, ctx);
    if (!r) { openssl_error("Failed to get curve params"); }

    BN_CTX_free(ctx);
    return SUCCESS;
}

int
ecelgamal_recv_ciphertext (
    int           sockfd,
    EcGamalCiphertext *c,
    EcGamalPk        *pk,
    char    *conf_prefix)
{
    int r;
    c->c1 = EC_POINT_new(pk->group);
    if (!c->c1) {r = 0; return openssl_error("Failed to alloc ciphertext c1");}
    c->c2 = EC_POINT_new(pk->group);
    if (!c->c2) {r = 0; return openssl_error("Failed to alloc ciphertext c2");}

    /* printf("%s\n", conf_prefix); */
    r = recv_msg(sockfd, &c->c1, "\t- c1 = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to recv ciphertext c1"); }
    r = recv_msg(sockfd, &c->c2, "\t- c1 = ", Ecpoint, pk->group);
    if (!r) { return general_error("Failed to recv ciphertext c2"); }
    return SUCCESS;
}
