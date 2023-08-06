#include "../../hdr/protocols/PLIca-ecelgamal-ah.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_pli_ca_ecelgamal_ah (
    int                  new_fd,
    int                 sec_par,
    char              *filename)
{
    int r;
    int nid;
    int num_entries = 0;
    int matches = 0;
    EcGamalKeys server_keys;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = generate_ecelgamal_keys(&server_keys, sec_par);
    if (!r) { return openssl_error("Failed to gen EG keys"); }

    /* Start here to exclude key generation */
    TSTART(sec_par);

    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }


    nid = EC_GROUP_get_curve_name(server_keys.pk->group);
    r = send_msg(new_fd, &nid, "server: sent server NID group =", Integer);
    if (!r) { return general_error("Failed to send NID group"); }
    r = send_msg(new_fd, server_keys.pk->order, "server: sent server order =", Bignum);
    if (!r) { return general_error("Failed to send order"); }
    r = send_msg(new_fd, server_keys.pk->generator, "server: sent server generator =",
		 Ecpoint, server_keys.pk->group);
    if (!r) { return general_error("Failed to send generator"); }
    r = send_msg(new_fd, server_keys.pk->point, "server: sent server point  =",
		 Ecpoint, server_keys.pk->group);
    if (!r) { return general_error("Failed to send point"); }


    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	r = ecelgamal_ah_encrypt(&server_cipher[i], server_keys.pk, bn_plain[i], sec_par);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	r = send_msg(new_fd, server_cipher[i].c1, "server: sent server_cipher.c1",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to send server_cipher.c1"); }
	r = send_msg(new_fd, server_cipher[i].c2, "server: sent server_cipher.c2",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to send server_cipher.c2"); }
    }


    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	client_cipher[i].c1 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c1, "server: recv client_cipher.c1",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to recv client_cipher.c1"); }

	client_cipher[i].c2 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c2, "server: recv client_cipher.c2",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to recv client_cipher.c2"); }
    }


    for (int i=0; i<num_entries; i++) {
	r = ecelgamal_skip_dlog_check_is_at_infinity(server_keys, client_cipher[i], &matches);
	if (!r) { return general_error("Failed skip decrypt check"); }
    }
    printf("# Matches = %*i\n", -3, matches);
    printf("# Misses  = %*i\n", -3, num_entries - matches);
    COLLECT_LOG_ENTRY(sec_par, num_entries, total_bytes);

    EC_GROUP_free(server_keys.pk->group);
    BN_free(server_keys.pk->order);
    EC_POINT_free(server_keys.pk->generator);
    EC_POINT_free(server_keys.pk->point);
    BN_free(server_keys.pk->p);
    BN_free(server_keys.pk->a);
    BN_free(server_keys.pk->b);
    free(server_keys.pk);
    BN_free(server_keys.sk);
    for (int i = 0; i < num_entries; i++) {
	EC_POINT_free(client_cipher[i].c1);
	EC_POINT_free(client_cipher[i].c2);
	EC_POINT_free(server_cipher[i].c1);
	EC_POINT_free(server_cipher[i].c2);
	BN_free(bn_plain[i]);
    }
    free(bn_plain);
    free(server_cipher);
    free(client_cipher);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
client_run_pli_ca_ecelgamal_ah (
    int                  sockfd,
    int                 sec_par,
    char *             filename)
{
    int r;
    int num_entries = 0;
    int nid = 0;
    EcGamalPk server_pk;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }


    r = recv_msg(sockfd, (void *)&nid, "client: received server group nid   = ", Integer);
    if (!r) { return general_error("Failed to recv server pk group"); }
    server_pk.group = EC_GROUP_new_by_curve_name(nid);
    server_pk.order = BN_new();
    r = recv_msg(sockfd, (void *)&server_pk.order, "client: received server order   = ", Bignum);
    if (!r) { return general_error("Failed to recv server pk order"); }
    server_pk.generator = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.generator, "client: received server generator   = ",
		 Ecpoint, server_pk.group);
    if (!r) { return general_error("Failed to recv server pk generator"); }
    server_pk.point = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.point, "client: received server point   = ",
		 Ecpoint, server_pk.group);
    if (!r) { return general_error("Failed to recv server pk point"); }
    server_pk.p = BN_new();
    server_pk.a = BN_new();
    server_pk.b = BN_new();
    r = EC_GROUP_get_curve(server_pk.group, server_pk.p, server_pk.a, server_pk.b, ctx);
    if (!r) { openssl_error("Failed to get curve params"); }

    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	server_cipher[i].c1 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c1, "client: received server_cipher.c1   = ",
		     Ecpoint, server_pk.group);
	if (!r) { return general_error("Failed to recv server_cipher.c1"); }
	server_cipher[i].c2 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c2, "client: received server_cipher.c2   = ",
		     Ecpoint, server_pk.group);
	if (!r) { return general_error("Failed to recv server_cipher.c2"); }
    }

    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i = 0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_inv_plain[i] = BN_dup(bn_plain[i]);
	BN_set_negative(bn_inv_plain[i], 1);
	if (!bn_inv_plain[i]) { openssl_error("Failed to negate bn_plain"); }
    }
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	r = ecelgamal_ah_encrypt(&client_cipher[i], &server_pk, bn_inv_plain[i], sec_par);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }

    EcGamalCiphertext add_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* add_res alloc'd within fn */
	r = ecelgamal_add(&add_res[i], server_cipher[i], client_cipher[i], server_pk);
	if (!r) { return general_error("Failed to calc server_ciph + client_ciph"); }
    }

    BIGNUM *bn_rand_mask[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.p, sec_par, ctx);
	if (!r) { return openssl_error("Failed to gen rand_mask"); }
    }

    EcGamalCiphertext *ptmul_res = calloc(num_entries, sizeof(*ptmul_res));
    for (int i = 0; i < num_entries; i++) {
	/* ptmul_res alloc'd w/n fn */
	r = ecelgamal_ptmul(&ptmul_res[i], add_res[i], bn_rand_mask[i], server_pk);
	if (!r) { return general_error("Failed to point mul the ciphertexts"); }
    }

    r = permute_ecelgamal_ciphertexts(&ptmul_res, (unsigned long)num_entries, server_pk.group);
    if (!r) { return general_error("Failed to permute ciphertext entries"); }

    for (int i = 0; i < num_entries; i++) {
	r = send_msg(sockfd, ptmul_res[i].c1, "client: sent ptmul_res.c1", Ecpoint, server_pk.group);
	if (!r) { general_error("Failed to send ptmul_res.c1"); }
	r = send_msg(sockfd, ptmul_res[i].c2, "client: sent ptmul_res.c2", Ecpoint, server_pk.group);
	if (!r) { general_error("Failed to send ptmul_res.c2"); }
    }

    EC_GROUP_free(server_pk.group);
    BN_free(server_pk.order);
    EC_POINT_free(server_pk.generator);
    EC_POINT_free(server_pk.point);
    BN_free(server_pk.p);
    BN_free(server_pk.a);
    BN_free(server_pk.b);
    for (int i = 0; i < num_entries; i++) {
	BN_free(bn_plain[i]);
	BN_free(bn_inv_plain[i]);
	BN_free(bn_rand_mask[i]);
	EC_POINT_free(add_res[i].c1);
	EC_POINT_free(add_res[i].c2);
	EC_POINT_free(ptmul_res[i].c1);
	EC_POINT_free(ptmul_res[i].c2);
	EC_POINT_free(client_cipher[i].c1);
	EC_POINT_free(client_cipher[i].c2);
	EC_POINT_free(server_cipher[i].c1);
	EC_POINT_free(server_cipher[i].c2);
    }
    free(ptmul_res);
    free(server_cipher);
    free(bn_plain);
    free(client_cipher);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
