#include "../../hdr/protocols/PLI-elgamal-mh.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_pli_elgamal_mh (
    int   new_fd,
    InputArgs ia)
{
    int r;
    GamalKeys server_keys;
    BN_CTX *ctx = BN_CTX_new();

    r = elgamal_generate_keys(&server_keys, ia.secpar);
    if (!r) { return openssl_error("Failed to gen EG keys"); }

    /* Start here to exclude key generation */
    TSTART(ia.secpar);

    BIGNUM *bn_plain[ia.num_entries];
    /* Fn alloc's each bn_plain[i] */
    r = parse_file_for_list_entries(bn_plain, ia.num_entries, ia.server_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    r = elgamal_send_pk(new_fd, server_keys.pk, "Server sent:");
    if (!r) { return general_error("Failed to send server pk"); }

    GamalCiphertext server_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's server_cipher fields */
	r = elgamal_mh_encrypt(&server_cipher[i], *server_keys.pk, bn_plain[i], ia.secpar);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	r = elgamal_send_ciphertext(new_fd, &server_cipher[i], "Server sent:");
	if (!r) { return general_error("Failed to send server ciphertext"); }
    }

    GamalCiphertext client_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's client_cipher fields */
	r = elgamal_recv_ciphertext(new_fd, &client_cipher[i], "Server recv:");
	if (!r) { return general_error("Failed to recv client ciphertext"); }
    }

    int matched = 0;
    for (size_t i = 0; i < ia.num_entries; i++) {
	r = elgamal_skip_decrypt_check_equality(&matched, server_keys, client_cipher[i]);
	if (!r) { return general_error("Failed during skip decrypt check"); }
	if (matched) {
	    printf("Matched on index -> %*zu with ", 3, i);
	    BN_print_fp(stdout, bn_plain[i]);
	    printf("\n");
	}
    }
    COLLECT_LOG_ENTRY(ia.secpar, ia.num_entries, total_bytes);

    BN_free(server_keys.pk->modulus);
    BN_free(server_keys.pk->generator);
    BN_free(server_keys.pk->mul_mask);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    for (size_t i = 0; i < ia.num_entries; i++) {
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
	BN_free(bn_plain[i]);
    }
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
client_run_pli_elgamal_mh (
    int   sockfd,
    InputArgs ia)
{
    int r;
    GamalPk server_pk;
    BN_CTX *ctx = BN_CTX_new();

    /* Fn alloc's server_pk fields */
    r = elgamal_recv_pk(sockfd, &server_pk, "Client recv:");
    if (!r) { return general_error("Failed to recv server pk"); }

    GamalCiphertext server_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's server_cipher fields */
	r = elgamal_recv_ciphertext(sockfd, &server_cipher[i], "Client recv:");
	if (!r) { return general_error("Failed to recv server ciphertext"); }
    }

    BIGNUM *bn_plain[ia.num_entries];
    /* Fn alloc's bn_plain[i] */
    r = parse_file_for_list_entries(bn_plain, ia.num_entries, ia.client_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    BIGNUM *bn_inv_plain[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	bn_inv_plain[i] = BN_mod_inverse(NULL, bn_plain[i], server_pk.modulus, ctx);
	if (!bn_inv_plain[i]) { r = 0; return openssl_error("Failed to invert bn_plain"); }
    }
    GamalCiphertext client_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's client_cipher fields */
	r = elgamal_mh_encrypt(&client_cipher[i], server_pk, bn_inv_plain[i], ia.secpar);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }
    GamalCiphertext mul_res[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* mul_res alloc'd within fn */
	r = elgamal_mul(&mul_res[i], server_cipher[i], client_cipher[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calc server_ciph * client_ciph"); }
    }
    BIGNUM *bn_rand_mask[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = generate_ec_equivalent_random_number(&bn_rand_mask[i], server_pk.modulus, ia.secpar);
	if (!r) { return openssl_error("Failed to gen rand_exp"); }
    }
    GamalCiphertext exp_res[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* exp_res alloc'd w/n fn */
	r = elgamal_exp(&exp_res[i], mul_res[i], bn_rand_mask[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calculate cipher^mask"); }
	r = elgamal_send_ciphertext(sockfd, &exp_res[i], "Client sent:");
	if (!r) { return general_error("Failed to send exp_res"); }
    }

    BN_free(server_pk.modulus);
    BN_free(server_pk.generator);
    BN_free(server_pk.mul_mask);
    for (size_t i = 0; i < ia.num_entries; i++) {
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
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
