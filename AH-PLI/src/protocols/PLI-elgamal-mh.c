#include "../../hdr/protocols/PLI-elgamal-mh.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_pli_elgamal_mh (
    int                  new_fd,
    int                 sec_par,
    char              *filename)
{
    int r;
    int num_entries = 0;
    int matches = 0;
    GamalKeys server_keys;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = elgamal_generate_keys(&server_keys, sec_par);
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

    r = elgamal_send_pk(new_fd, server_keys.pk, "Server sent:");
    if (!r) { return general_error("Failed to send server pk"); }

    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	r = elgamal_mh_encrypt(&server_cipher[i], *server_keys.pk, bn_plain[i], sec_par);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	r = elgamal_send_ciphertext(new_fd, &server_cipher[i], "Server sent:");
	if (!r) { return general_error("Failed to send server ciphertext"); }
    }

    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	/* Fn alloc's client_cipher[i].c1/c2 */
	r = elgamal_recv_ciphertext(new_fd, &client_cipher[i], "Server recv:");
	if (!r) { return general_error("Failed to recv client ciphertext"); }
    }

    for (int i = 0; i < num_entries; i++) {
	r = elgamal_skip_decrypt_check_equality(server_keys, client_cipher[i], &matches);
	if (!r) { return general_error("Failed skip decrypt check"); }
    }
    printf("# Matches = %*i\n", -3, matches);
    printf("# Misses  = %*i\n", -3, num_entries - matches);
    COLLECT_LOG_ENTRY(sec_par, num_entries, total_bytes);

    BN_free(server_keys.pk->modulus);
    BN_free(server_keys.pk->generator);
    BN_free(server_keys.pk->mul_mask);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    for (int i = 0; i < num_entries; i++) {
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
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
client_run_pli_elgamal_mh (
    int                  sockfd,
    int                 sec_par,
    char *             filename)
{
    int r;
    int num_entries = 0;
    GamalPk server_pk;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Fn alloc's server_pk fields */
    r = elgamal_recv_pk(sockfd, &server_pk, "Client recv:");
    if (!r) { return general_error("Failed to recv server pk"); }

    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	/* Fn alloc's server_cipher[i].c1/c2 */
	r = elgamal_recv_ciphertext(sockfd, &server_cipher[i], "Client recv:");
	if (!r) { return general_error("Failed to recv server ciphertext"); }
    }

    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_inv_plain[i] = BN_mod_inverse(NULL, bn_plain[i], server_pk.modulus, ctx);
	if (!bn_inv_plain[i]) { r = 0; return openssl_error("Failed to invert bn_plain"); }
    }
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	r = elgamal_mh_encrypt(&client_cipher[i], server_pk, bn_inv_plain[i], sec_par);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }
    GamalCiphertext mul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* mul_res alloc'd within fn */
	r = elgamal_mul(&mul_res[i], server_cipher[i], client_cipher[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calc server_ciph * client_ciph"); }
    }
    BIGNUM *bn_rand_mask[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	switch (sec_par) {
	case 2048:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, 224, ctx);
	    break;
	case 1024:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, 160, ctx);
	    break;
	default:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, sec_par, ctx);
	    break;
	}
	if (!r) { return openssl_error("Failed to gen rand_exp"); }
    }
    GamalCiphertext exp_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* exp_res alloc'd w/n fn */
	r = elgamal_exp(&exp_res[i], mul_res[i], bn_rand_mask[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calculate cipher^mask"); }
	r = elgamal_send_ciphertext(sockfd, &exp_res[i], "Client sent:");
	if (!r) { return general_error("Failed to send exp_res"); }
    }

    BN_free(server_pk.modulus);
    BN_free(server_pk.generator);
    BN_free(server_pk.mul_mask);
    for (int i = 0; i < num_entries; i++) {
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
	BN_free(bn_plain[i]);
	BN_free(bn_inv_plain[i]);
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(mul_res[i].c1);
	BN_free(mul_res[i].c2);
	BN_free(bn_rand_mask[i]);
	BN_free(exp_res[i].c1);
	BN_free(exp_res[i].c2);
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
