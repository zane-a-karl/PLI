#include <stdlib.h>	                // size_t
#include <openssl/bn.h>	                // BIGNUM
#include <openssl/ec.h>	                // EC_POINT
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
#include "../../hdr/protocols/PLIca-ecelgamal-ah.h"
#include "../../hdr/ecelgamal/utils.h"	// EcGamalKeys
#include "../../hdr/error/utils.h"	// openssl_error()
#include "../../hdr/logging/utils.h"	// TSTART()
#include "../../hdr/ecelgamal/ah-utils.h" // ecelgamal_ah_encrypt()


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_pli_ca_ecelgamal_ah (
    int   new_fd,
    InputArgs ia)
{
    int r;
    EcGamalKeys server_keys;
    BN_CTX *ctx = BN_CTX_new();

    r = ecelgamal_generate_keys(&server_keys, ia.secpar);
    if (!r) { return openssl_error("Failed to gen EG keys"); }

    /* Start here to exclude key generation */
    TSTART(ia.secpar, ia.log_filename);

    BIGNUM *bn_plain[ia.num_entries];
    /* Fn alloc's each bn_plain[i] */
    r = parse_file_for_list_entries(bn_plain, ia.num_entries, ia.server_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    r = ecelgamal_send_pk(new_fd, server_keys.pk, "Server sent:");
    if (!r) { return general_error("Failed to send server pk"); }

    EcGamalCiphertext server_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's server_cipher fields */
	r = ecelgamal_ah_encrypt(&server_cipher[i], server_keys.pk, bn_plain[i], ia.secpar);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	r = ecelgamal_send_ciphertext(new_fd, &server_cipher[i], server_keys.pk, "Server sent:");
	if (!r) { return general_error("Failed to send server ciphertext"); }
    }

    EcGamalCiphertext client_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's client_cipher fields */
	r = ecelgamal_recv_ciphertext(new_fd, &client_cipher[i], server_keys.pk, "Server recv:");
	if (!r) { return general_error("Failed to recv client ciphertext"); }
    }

    size_t cardinality = 0;
    int matched = 0;
    for (size_t i = 0; i < ia.num_entries; i++) {
	r = ecelgamal_skip_dlog_check_is_at_infinity(&matched, server_keys, client_cipher[i]);
	if (!r) { return general_error("Failed skip decrypt check"); }
	cardinality += matched;
    }
    printf("Intersection Cardinality = %*zu\n", -3, cardinality);
    COLLECT_LOG_ENTRY(ia.secpar, ia.num_entries, ia.threshold, ia.expected_matches, total_bytes);

    EC_GROUP_free(server_keys.pk->group);
    BN_free(server_keys.pk->order);
    EC_POINT_free(server_keys.pk->generator);
    EC_POINT_free(server_keys.pk->point);
    BN_free(server_keys.pk->p);
    BN_free(server_keys.pk->a);
    BN_free(server_keys.pk->b);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    for (size_t i = 0; i < ia.num_entries; i++) {
	EC_POINT_free(client_cipher[i].c1);
	EC_POINT_free(client_cipher[i].c2);
	EC_POINT_free(server_cipher[i].c1);
	EC_POINT_free(server_cipher[i].c2);
	BN_free(bn_plain[i]);
    }
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
client_run_pli_ca_ecelgamal_ah (
    int   sockfd,
    InputArgs ia)
{
    int r;
    EcGamalPk server_pk;
    BN_CTX *ctx = BN_CTX_new();

    /* Fn alloc's server_pk fields */
    r = ecelgamal_recv_pk(sockfd, &server_pk, "Client recv:");
    if (!r) { return general_error("Failed to recv server pk"); }

    EcGamalCiphertext server_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's server_cipher fields */
	r = ecelgamal_recv_ciphertext(sockfd, &server_cipher[i], &server_pk, "Client recv:");
	if (!r) { return general_error("Failed to recv server ciphertext"); }
    }

    BIGNUM *bn_plain[ia.num_entries];
    /* Fn alloc's bn_plain[i] */
    r = parse_file_for_list_entries(bn_plain, ia.num_entries, ia.client_filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }

    BIGNUM *bn_inv_plain[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	bn_inv_plain[i] = BN_dup(bn_plain[i]);
	BN_set_negative(bn_inv_plain[i], 1);
	if (!bn_inv_plain[i]) { openssl_error("Failed to negate bn_plain"); }
    }
    EcGamalCiphertext client_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's client_cipher fields */
	r = ecelgamal_ah_encrypt(&client_cipher[i], &server_pk, bn_inv_plain[i], ia.secpar);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }
    EcGamalCiphertext add_res[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* add_res alloc'd within fn */
	r = ecelgamal_add(&add_res[i], server_cipher[i], client_cipher[i], server_pk);
	if (!r) { return general_error("Failed to calc server_ciph + client_ciph"); }
    }
    BIGNUM *bn_rand_mask[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.p, ia.secpar, ctx);
	if (!r) { return openssl_error("Failed to gen rand_mask"); }
    }
    EcGamalCiphertext ptmul_res[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* ptmul_res alloc'd w/n fn */
	r = ecelgamal_ptmul(&ptmul_res[i], add_res[i], bn_rand_mask[i], server_pk);
	if (!r) { return general_error("Failed to point mul the ciphertexts"); }
    }
    r = ecelgamal_permute_ciphertexts(ptmul_res, (unsigned long)ia.num_entries, server_pk.group);
    if (!r) { return general_error("Failed to permute ciphertext entries"); }
    for (size_t i = 0; i < ia.num_entries; i++) {
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
    for (size_t i = 0; i < ia.num_entries; i++) {
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
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
