#include <stdlib.h>	                // size_t
#include <openssl/bn.h>	                // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include <netdb.h>                      // struct sockaddr
#include "../../hdr/elgamal/utils.h"	// GamalCiphertext
#include <openssl/ec.h>	                // EC_POINT
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
#include "../../hdr/protocols/tPLIca-elgamal-mh.h"
#include "../../hdr/error/utils.h"	    // openssl_error()
#include "../../hdr/logging/utils.h"	    // TSTART()
#include "../../hdr/elgamal/mh-utils.h"     // elgamal_mh_encrypt()
#include "../../hdr/network/utils.h"	    // recv_msg()
#include "../../hdr/elgamal/thresholding.h" // elgamal_server_thresholding()


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

int
server_run_t_pli_ca_elgamal_mh (
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
	/* Client only sends c1 so Server doesn't need c2,
	   but I use it as a tmp storage space in the
	   thresholding function so I alloc it here. */
	client_cipher[i].c1 = BN_new();
	client_cipher[i].c2 = BN_new();
	r = recv_msg(new_fd, &client_cipher[i].c1, "Server recv client ctxt.c1: ", Bignum);
	if (!r) { return general_error("Failed to recv client_ciphertext.c1"); }
    }

    /* Elgamal-based Server side thresholding protocol */
    size_t matches[ia.num_entries];
    size_t cardinality = 0;
    r = elgamal_server_thresholding(matches, new_fd, server_keys, client_cipher, ia);
    if (!r) { return general_error("Failed during elgamal_server_thresholding"); }
    for (size_t i = 0; i < ia.num_entries; i++) {
	cardinality += matches[i];
    }
    if (cardinality >= ia.threshold) {
	printf("Intersection Cardinality = %*zu\n", -3, cardinality);
    } else {
	printf("Failed to meet threshold");
    }
    COLLECT_LOG_ENTRY(ia.secpar, ia.num_entries, total_bytes);

    BN_free(server_keys.pk->modulus);
    BN_free(server_keys.pk->generator);
    BN_free(server_keys.pk->mul_mask);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    for (size_t i = 0; i < ia.num_entries; i++) {
	BN_free(bn_plain[i]);
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
    }
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
client_run_t_pli_ca_elgamal_mh (
    int   sockfd,
    InputArgs ia)
{
    int r;
    /* int num_entries = 0; */
    GamalPk server_pk;
    BN_CTX *ctx = BN_CTX_new();

    /* r = parse_file_for_num_entries(&num_entries, ia.client_filename); */
    /* if (!r) { return general_error("Failed to parse file for number of list entries"); } */

    /* Fn alloc's server_pk fields */
    r = elgamal_recv_pk(sockfd, &server_pk, "Client recv:");
    if (!r) { return general_error("Failed to recv server pk"); }

    GamalCiphertext server_cipher[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's server_cipher[i].c1/c2 */
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
	switch (ia.secpar) {
	case 1024:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, 160, ctx);
	    break;
	case 2048:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, 224, ctx);
	    break;
	default:
	    r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, ia.secpar, ctx);
	    break;
	}
	if (!r) { return openssl_error("Failed to gen rand_exp"); }
    }
    GamalCiphertext exp_res[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* exp_res alloc'd w/n fn */
	r = elgamal_exp(&exp_res[i], mul_res[i], bn_rand_mask[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calculate cipher^mask"); }
    }
    r = elgamal_permute_ciphertexts(exp_res, (unsigned long)ia.num_entries);
    if (!r) { return general_error("Failed to permute ciphertext entries"); }
    for (size_t i = 0; i < ia.num_entries; i++) {
	r = send_msg(sockfd, exp_res[i].c1, "Client sent exp_res[i].c1:", Bignum);
	if (!r) { return general_error("Failed to send exp_res[i].c1"); }
    }

    /* Elgamal-based client side thresholding protocol */
    r = elgamal_client_thresholding(sockfd, server_pk, exp_res, ia);
    if (!r) { return general_error("Failed during elgamal_client_thresholding"); }

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
