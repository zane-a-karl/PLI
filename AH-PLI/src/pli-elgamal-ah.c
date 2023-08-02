#include "../hdr/pli-elgamal-ah.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

/* #define TSTART(sec_par)							\ */
/*     snprintf(logfile, 32, "%s-%s-%d.%s", "logs/elgamal", "AH", sec_par, "csv"); \ */
/*     logfs = fopen(logfile, "a");					\ */
/*     printf("Starting the clock: \n");					\ */
/*     clock_gettime(CLOCK_MONOTONIC, &t1); */
#define TSTART(sec_par)				\
    logfs = stdout;				\
    printf("Starting the clock: \n");		\
    clock_gettime(CLOCK_MONOTONIC, &t1);

#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2);			\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs,"Line:%5d, Time = %f\n",__LINE__,sec);

#define COLLECT_LOG_ENTRY(sec_par, n_entries, bytes)			\
    printf("Ending the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t2);				\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs, "%d, ", sec_par);					\
    fprintf(logfs, "%d, ", n_entries);					\
    fprintf(logfs, "%" PRIu64 ", ", bytes);				\
    fprintf(logfs,"%f\n", sec);						\
    fclose(logfs);

int
server_run_pli_elgamal_ah (
    int                  new_fd,
    int                 sec_par,
    char              *filename)
{
    logfile = calloc(32, sizeof(char));
    /* TSTART(sec_par); */
    int r;
    int num_entries = 0;
    GamalKeys server_keys;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    // Generate Keys
    /* printf("Started generating server keys\n"); TTICK; */
    r = generate_elgamal_keys(&server_keys, sec_par);
    if (!r) { return openssl_error("Failed to gen EG keys"); }
    /* printf("Finished generating server keys\n\n"); TTICK; */

    // Start here to exclude key generation
    TSTART(sec_par);

    // Parse number of list entries from <filename>
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    // Parse server list entries from <filename>
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    /* r = generate_list_entries(&plain, num_entries); */
    if (!r) { return general_error("Failed to parse file for list entries"); }
    /* printf("parsed server list\n"); */

    // Send server pk to client
    /* printf("Started sending server pk\n"); TTICK; */
    // 1st: the modulus
    r = send_msg(new_fd, server_keys.pk->modulus, "server: sent server modulus   =", Bignum);
    if (!r) { return general_error("Failed to send modulus"); }
    // 2nd: the generator
    r = send_msg(new_fd, server_keys.pk->generator, "server: sent server generator =", Bignum);
    if (!r) { return general_error("Failed to send generator"); }
    // 3rd: the mul_mask
    r = send_msg(new_fd, server_keys.pk->mul_mask, "server: sent server mul_mask  =", Bignum);
    if (!r) { return general_error("Failed to send mul_mask"); }
    /* printf("Finished sending server pk\n\n"); TTICK; */

    /* Encrypt server list entries and send them to client */
    /* printf("Started sending Enc_pkS(server list)\n"); TTICK; */
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	r = ah_elgamal_encrypt(&server_cipher[i], *server_keys.pk, bn_plain[i], sec_par);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	// Send C1
	r = send_msg(new_fd, server_cipher[i].c1, "server: sent server_cipher.c1", Bignum);
	if (!r) { return general_error("Failed to send server_cipher.c1"); }
	// Send C2
	r = send_msg(new_fd, server_cipher[i].c2, "server: sent server_cipher.c2", Bignum);
	if (!r) { return general_error("Failed to send server_cipher.c2"); }
    }
    /* printf("Finished sending Enc_pkS(server list)\n\n"); TTICK; */

    /* Receive exp_res entries from client */
    /* printf("Started receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK; */
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	// Recv C1
	client_cipher[i].c1 = BN_new();
	if (!client_cipher[i].c1) {r = 0; return openssl_error("Failed to alloc client_cipher.c1");}
	r = recv_msg(new_fd, &client_cipher[i].c1, "server: recv client_cipher.c1", Bignum);
	if (!r) { return general_error("Failed to recv client_cipher.c1"); }
	// Recv C2
	client_cipher[i].c2 = BN_new();
	if (!client_cipher[i].c2) {r = 0; return openssl_error("Failed to alloc client_cipher.c2"); }
	r = recv_msg(new_fd, &client_cipher[i].c2, "server: recv client_cipher.c2", Bignum);
	if (!r) { return general_error("Failed to recv client_cipher.c2"); }
    }
    /* printf("Finished receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n\n"); TTICK; */

    /* Skip decryption and just check c2 == c1^sk */
    /* printf("Started pli ciphertext comparison\n"); TTICK; */
    for (int i=0; i<num_entries; i++) {
	printf("Check#%*i -> ", -3, i);
	r = elgamal_skip_dlog_check_is_one(server_keys, client_cipher[i]);
	if(!r) { return general_error("Failed skip decrypt check"); }
    }
    /* printf("Finished pli ciphertext comparison\n\n"); TTICK; */
    /* printf("Total bytes sent during protocol = %" PRIu64 "\n", total_bytes); */
    COLLECT_LOG_ENTRY(sec_par, num_entries, total_bytes);

    free(logfile);
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
client_run_pli_elgamal_ah (
    int                  sockfd,
    int                 sec_par,
    char *             filename)
{
    /* TSTART(sec_par); */
    int r;
    int num_entries = 0;
    GamalPk server_pk;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();
    /* Parse number of list entries from <filename> */
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Receive server_pk via socket */
    /* printf("Started receiving server pk\n"); TTICK; */
    // 1st: the modulus
    server_pk.modulus = BN_new();
    r = recv_msg(sockfd, &server_pk.modulus, "client: received server modulus   = ", Bignum);
    if (!r) { return general_error("Failed to recv server modulus"); }

    /* 2nd: the generator */
    server_pk.generator = BN_new();
    r = recv_msg(sockfd, &server_pk.generator, "client: received server generator   = ", Bignum);
    if (!r) { return general_error("Failed to recv server generator"); }

    /* 3rd: the mul_mask */
    server_pk.mul_mask = BN_new();
    r = recv_msg(sockfd, &server_pk.mul_mask, "client: received server mul_mask   = ", Bignum);
    if (!r) { return general_error("Failed to recv server mul_mask"); }
    /* printf("Finished receiving server pk\n"); TTICK; */

    /* Receive ciphertext in two sequential messages of c1 and c2 */
    /* printf("Started receiving Enc_pkS(server list)\n"); TTICK; */
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	/* Receive c1 */
	server_cipher[i].c1 = BN_new();
	r = recv_msg(sockfd, &server_cipher[i].c1, "client: received server_cipher.c1   = ", Bignum);
	if (!r) { return general_error("Failed to recv server_cipher.c1"); }
	/* Receive c2 */
	server_cipher[i].c2 = BN_new();
	r = recv_msg(sockfd, &server_cipher[i].c2, "client: received server_cipher.c2   = ", Bignum);
	if (!r) { return general_error("Failed to recv server_cipher.c2"); }
    }
    /* printf("Finished receiving Enc_pkS(server list)\n\n"); TTICK; */

    /* Parse client list entries from <filename> */
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    /* r = generate_list_entries(&plain, num_entries); */
    if (!r) { return general_error("Failed to parse file for list entries"); }
    /* printf("parsed client list\n"); */

    /* Calculate the negation/mult inv of the client list entries */
    /* printf("Started computing (Enc_pkS(server list) * Enc_pkS(inv client list))^mask \n"); TTICK; */
    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_inv_plain[i] = BN_dup(bn_plain[i]);
	if (!bn_inv_plain[i]) { r = 0; return openssl_error("Failed to duplicate bn_plain"); }
	BN_set_negative(bn_inv_plain[i], 1);

    }
    /* Encrypt inverse of client list entries under the server public key */
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	r = ah_elgamal_encrypt(&client_cipher[i], server_pk, bn_inv_plain[i], sec_par);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }

    /* Multiply the server and client ciphertexts */
    GamalCiphertext mul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* mul_res alloc'd within fn */
	r = elgamal_mul(&mul_res[i], server_cipher[i], client_cipher[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calc server_ciph * client_ciph"); }
    }

    /* Generate a random masking value */
    BIGNUM *bn_rand_mask[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.modulus, sec_par, ctx);
	if (!r) { return openssl_error("Failed to gen rand_exp"); }
    }
    /* printf("generated random masking value\n"); */

    /* Raise product of ciphertext to the random value 'bn_rand_mask' */
    GamalCiphertext exp_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* exp_res alloc'd w/n fn */
	r = elgamal_exp(&exp_res[i], mul_res[i], bn_rand_mask[i], server_pk.modulus);
	if (!r) { return general_error("Failed to calculate cipher^mask"); }
    }
    /* printf("Finished computing (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */

    /* Send exp_res to the server */
    /* printf("Started sending (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */
    for (int i = 0; i < num_entries; i++) {
	/* Send c1 */
	r = send_msg(sockfd, exp_res[i].c1, "client: sent exp_res.c1", Bignum);
	if (!r) { return general_error("Failed to send exp_res.c1"); }
	/* Send c2 */
	r = send_msg(sockfd, exp_res[i].c2, "client: sent exp_res.c2", Bignum);
	if (!r) { return general_error("Failed to send exp_res.c2"); }
    }
    /* printf("Finished sending (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */

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
