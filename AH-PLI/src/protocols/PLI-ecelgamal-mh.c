#include "../../hdr/protocols/PLI-ecelgamal-mh.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_pli_ecelgamal_mh (
    int   new_fd,
    InputArgs ia)
{
    int r;
    int num_entries = 0;
    int matches = 0;
    EcGamalKeys server_keys;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = ecelgamal_generate_keys(&server_keys, ia.secpar);
    if (!r) { return openssl_error("Failed to gen EG keys"); }

    /* Start here to exclude key generation */
    TSTART(ia.secpar);

    r = parse_file_for_num_entries(&num_entries, ia.server_filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, ia.server_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    /* Precompute some ec points and then get them from a file later */
    /* BIGNUM *x = BN_new(); */
    /* BIGNUM *y = BN_new(); */
    /* EC_POINT *p = EC_POINT_new(server_keys.pk->group); */
    /* char *xx = calloc(40, sizeof(char)); */
    /* bn_plain = calloc(num_entries, sizeof(*bn_plain));     */
    /* for (int i = 0; i < num_entries; i++) { */
    /* 	bn_plain[i] = BN_new(); */
    /* 	r = BN_set_word(bn_plain[i], plain[i]); */
    /* 	if (!r) { perror("Failed to set ptxt2bn"); return FAILURE; }	 */
    /* 	r = EC_POINT_mul(server_keys.pk->group, p, bn_plain[i], NULL, NULL, ctx); */
    /* 	if (!r) { perror("Failed to calc G(rand)"); return FAILURE; } */
    /* 	r = EC_POINT_get_affine_coordinates(server_keys.pk->group, p, */
    /* 					    x, y, ctx); */
    /* 	if (!r) {perror("Failed to get affine coords"); return FAILURE; } */
    /* 	xx = BN_bn2dec(x);	 */
    /* 	printf("x = "); printf("%s", xx); printf("\n"); */
    /* 	for (int j = 0; j < 40; j++) { */
    /* 	    printf("iteration#%i,  ", j); */
    /* 	    xx[j] = 0; */
    /* 	} */
    /* } */
    /* BN_free(x); BN_free(y); EC_POINT_free(p); */
    /* return FAILURE;     */

    r = ecelgamal_send_pk(new_fd, server_keys.pk, "Server sent:");
    if (!r) { return general_error("Failed to send server pk"); }

    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	r = ecelgamal_mh_encrypt(&server_cipher[i], server_keys.pk, bn_plain[i], ia.secpar);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	r = ecelgamal_send_ciphertext(new_fd, &server_cipher[i], server_keys.pk, "Server sent:");
	if (!r) { return general_error("Failed to send server ciphertext"); }
    }

    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	/* Fn alloc's client_cipher[i].c1/c2 */
	r = ecelgamal_recv_ciphertext(new_fd, &client_cipher[i], server_keys.pk, "Server recv:");
	if (!r) { return general_error("Failed to recv client ciphertext"); }
    }

    /* Skip decryption and just check c2 == c1*sk */
    for (int i=0; i<num_entries; i++) {
	r = ecelgamal_skip_decrypt_check_equality(server_keys, client_cipher[i], &matches);
	if (!r) { return general_error("Failed skip decrypt check"); }
    }
    printf("# Matches = %*i\n", -3, matches);
    printf("# Misses  = %*i\n", -3, num_entries - matches);
    COLLECT_LOG_ENTRY(ia.secpar, num_entries, total_bytes);

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
client_run_pli_ecelgamal_mh (
    int   sockfd,
    InputArgs ia)
{
    int r;
    int num_entries = 0;
    EcGamalPk server_pk;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = parse_file_for_num_entries(&num_entries, ia.client_filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Fn alloc's server_pk fields */
    r = ecelgamal_recv_pk(sockfd, &server_pk, "Client recv:");
    if (!r) { return general_error("Failed to recv server pk"); }

    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	/* Fn alloc's server_cipher[i].c1/c2 */
	r = ecelgamal_recv_ciphertext(sockfd, &server_cipher[i], &server_pk, "Client recv:");
	if (!r) { return general_error("Failed to recv server ciphertext"); }
    }

    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i = 0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, ia.client_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_inv_plain[i] = BN_mod_inverse(NULL, bn_plain[i], server_pk.p, ctx);
	if (!bn_inv_plain[i]) { r = 0; return openssl_error("Failed to invert bn_plain"); }
    }
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	r = ecelgamal_mh_encrypt(&client_cipher[i], &server_pk, bn_inv_plain[i], ia.secpar);
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
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.p, ia.secpar, ctx);
	if (!r) { return openssl_error("Failed to gen rand_mask"); }
    }
    EcGamalCiphertext ptmul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* ptmul_res alloc'd w/n fn */
	r = ecelgamal_ptmul(&ptmul_res[i], add_res[i], bn_rand_mask[i], server_pk);
	if (!r) { return general_error("Failed to point mul the ciphertexts"); }
	r = ecelgamal_send_ciphertext(sockfd, &ptmul_res[i], &server_pk, "Client sent:");
	if (!r) { return general_error("Failed to send exp_res"); }
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
    free(server_cipher);
    free(bn_plain);
    free(client_cipher);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
