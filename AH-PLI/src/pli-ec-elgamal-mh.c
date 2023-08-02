#include "../hdr/pli-ec-elgamal-mh.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

/* #define TSTART(sec_par)						\ */
/*     snprintf(logfile, 32, "%s-%s-%d.%s", "logs/ec-elgamal", "MH", sec_par, "csv"); \ */
/*     logfs = fopen(logfile, "a");					\ */
/*     printf("Starting the clock: \n");					\ */
/*     clock_gettime(CLOCK_MONOTONIC, &t1); */
#define TSTART(sec_par)	      \
    logfs = stdout;		      \
    printf("Starting the clock: \n"); \
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
server_run_pli_ec_elgamal_mh (
    int                  new_fd,
    int                 sec_par,
    char              *filename)
{
    logfile = calloc(32, sizeof(char));
    /* TSTART(sec_par); */
    int r;
    int nid;
    int num_entries = 0;
    EcGamalKeys server_keys;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    // Generate Keys
    /* printf("Started generating server keys\n"); TTICK; */
    r = generate_ec_elgamal_keys(&server_keys, sec_par);
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

    // Send server pk to client
    /* printf("Started sending server pk\n"); TTICK; */
    // 1st: the NID of group
    nid = EC_GROUP_get_curve_name(server_keys.pk->group);
    r = send_msg(new_fd, &nid, "server: sent server NID group =", Integer);
    if (!r) { return general_error("Failed to send NID group"); }
    // 2nd: the order
    r = send_msg(new_fd, server_keys.pk->order, "server: sent server order =", Bignum);
    if (!r) { return general_error("Failed to send order"); }
    // 3rd: the generator
    r = send_msg(new_fd, server_keys.pk->generator, "server: sent server generator =",
		 Ecpoint, server_keys.pk->group);
    if (!r) { return general_error("Failed to send generator"); }
    // 4th: the point
    r = send_msg(new_fd, server_keys.pk->point, "server: sent server point  =",
		 Ecpoint, server_keys.pk->group);
    if (!r) { return general_error("Failed to send point"); }
    /* printf("Finished sending server pk\n\n"); TTICK; */

    /* Encrypt server list entries and send them to client */
    /* printf("Started sending Enc_pkS(server list)\n"); TTICK; */
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	r = mh_ec_elgamal_encrypt(&server_cipher[i], server_keys.pk, bn_plain[i], sec_par);
	if (!r) { return general_error("Failed to encrypt server plaintext"); }
	// Send C1
	r = send_msg(new_fd, server_cipher[i].c1, "server: sent server_cipher.c1",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to send server_cipher.c1"); }
	// Send C2
	r = send_msg(new_fd, server_cipher[i].c2, "server: sent server_cipher.c2",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to send server_cipher.c2"); }
    }
    /* printf("Finished sending Enc_pkS(server list)\n\n"); TTICK; */

    /* Receive exp_res entries from client */
    /* printf("Started receiving mask(Enc_pkS(server list) * Enc_pkS(inv client list))\n"); TTICK; */
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	// Recv C1
	client_cipher[i].c1 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c1, "server: recv client_cipher.c1",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to recv client_cipher.c1"); }
	// Recv C2
	client_cipher[i].c2 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c2, "server: recv client_cipher.c2",
		     Ecpoint, server_keys.pk->group);
	if (!r) { return general_error("Failed to recv client_cipher.c2"); }
    }
    /* printf("Finished receiving masked Enc_pkS(server list) + Enc_pkS(inv client list)\n\n"); TTICK; */

    /* Skip decryption and just check c2 == c1*sk */
    /* printf("Started pli ciphertext comparison\n"); TTICK; */
    for (int i=0; i<num_entries; i++) {
	printf("Check#%*i -> ", -3, i);
	r = ec_elgamal_skip_decrypt_check_equality(server_keys, client_cipher[i]);
	if(!r) { return general_error("Failed skip decrypt check"); }
    }
    /* printf("Finished pli ciphertext comparison\n\n"); TTICK; */
    /* printf("Total bytes sent during protocol = %" PRIu64 "\n", total_bytes); */
    COLLECT_LOG_ENTRY(sec_par, num_entries, total_bytes);

    free(logfile);
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
client_run_pli_ec_elgamal_mh (
    int                  sockfd,
    int                 sec_par,
    char *             filename)
{
    /* TSTART(sec_par); */
    int r;
    int num_entries = 0;
    int nid = 0;
    EcGamalPk server_pk;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    /* Parse number of list entries from <filename> */
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Receive server pk via socket */
    /* printf("Started receiving server pk\n"); TTICK; */
    /* 1st: the NID of group */
    r = recv_msg(sockfd, (void *)&nid, "client: received server group nid   = ", Integer);
    if (!r) { return general_error("Failed to recv server pk group"); }
    server_pk.group = EC_GROUP_new_by_curve_name(nid);

    /* 2nd: the order */
    server_pk.order = BN_new();
    r = recv_msg(sockfd, (void *)&server_pk.order, "client: received server order   = ", Bignum);
    if (!r) { return general_error("Failed to recv server pk order"); }

    /* 3rd: the generator */
    server_pk.generator = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.generator, "client: received server generator   = ",
		 Ecpoint, server_pk.group);
    if (!r) { return general_error("Failed to recv server pk generator"); }

    /* 4th: the point */
    server_pk.point = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.point, "client: received server point   = ",
		 Ecpoint, server_pk.group);
    if (!r) { return general_error("Failed to recv server pk point"); }

    /* 5th: the parameters p, a, and b */
    server_pk.p = BN_new();
    server_pk.a = BN_new();
    server_pk.b = BN_new();
    r = EC_GROUP_get_curve(server_pk.group, server_pk.p, server_pk.a, server_pk.b, ctx);
    if (!r) { openssl_error("Failed to get curve params"); }
    /* printf("pk.p = "); BN_print_fp(stdout, server_pk.p); printf("\n"); */
    /* printf("pk.a = "); BN_print_fp(stdout, server_pk.a); printf("\n"); */
    /* printf("pk.b = "); BN_print_fp(stdout, server_pk.b); printf("\n"); */
    /* printf("Finished receiving server pk\n"); TTICK; */

    /* Receive ciphertext in two sequential messages of c1 and c2 */
    /* printf("Started receiving Enc_pkS(server list)\n"); TTICK; */
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	/* Receive c1 */
	server_cipher[i].c1 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c1, "client: received server_cipher.c1   = ",
		     Ecpoint, server_pk.group);
	if (!r) { return general_error("Failed to recv server_cipher.c1"); }
	/* Receive c2 */
	server_cipher[i].c2 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c2, "client: received server_cipher.c2   = ",
		     Ecpoint, server_pk.group);
	if (!r) { return general_error("Failed to recv server_cipher.c2"); }
    }
    /* printf("Finished receiving Enc_pkS(server list)\n\n"); TTICK; */

    /* Parse client list entries from <filename> */
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i = 0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    /* r = generate_list_entries(&plain, num_entries); */
    if (!r) { return general_error("Failed to parse file for list entries"); }
    /* printf("parsed client list\n"); */

    /* Calculate the neg of the client list entries */
    /* printf("Started computing mask(Enc_pkS(server list) * Enc_pkS(neg client list))\n"); TTICK; */
    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_inv_plain[i] = BN_mod_inverse(NULL, bn_plain[i], server_pk.p, ctx);
	if (!bn_inv_plain[i]) { r = 0; return openssl_error("Failed to invert bn_plain"); }
    }
    /* Encrypt negation of client list entries under the server public key */
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	r = mh_ec_elgamal_encrypt(&client_cipher[i], &server_pk, bn_inv_plain[i], sec_par);
	if (!r) { return general_error("Error encrypting bn_inv_plain"); }
    }

    /* Add the server and client ciphertexts */
    EcGamalCiphertext add_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* add_res alloc'd within fn */
	r = ec_elgamal_add(&add_res[i], server_cipher[i], client_cipher[i], server_pk);
	if (!r) { return general_error("Failed to calc server_ciph + client_ciph"); }
    }

    /* Generate a random masking value */
    BIGNUM *bn_rand_mask[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.p, sec_par, ctx);
	if (!r) { return openssl_error("Failed to gen rand_mask"); }
	/* printf("r[%i] = ", i); */
	/* r = BN_print_fp(stdout, bn_rand_mask[i]); */
	/* printf("\n"); */
	/* if (!r) { return openssl_error("Failed to print bn_rand_mask"); } */
    }
    /* printf("generated random masking value\n"); */

    /* Point multiply the sum of the ciphertexts by the random value 'bn_rand_mask' */
    EcGamalCiphertext ptmul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* ptmul_res alloc'd w/n fn */
	r = ec_elgamal_ptmul(&ptmul_res[i], add_res[i], bn_rand_mask[i], server_pk);
	if (!r) { return general_error("Failed to point mul the ciphertexts"); }
    }
    /* printf("Finished computing mask(Enc_pkS(server list) + Enc_pkS(neg client list))\n"); TTICK; */

    /* Send ptmul_res to the server */
    /* printf("Started sending mask(Enc_pkS(server list) + Enc_pkS(neg client list))\n"); TTICK; */
    for (int i = 0; i < num_entries; i++) {
	/* Send c1 */
	r = send_msg(sockfd, ptmul_res[i].c1, "client: sent ptmul_res.c1", Ecpoint, server_pk.group);
	if (!r) { general_error("Failed to send ptmul_res.c1"); }
	/* Send c2 */
	r = send_msg(sockfd, ptmul_res[i].c2, "client: sent ptmul_res.c2", Ecpoint, server_pk.group);
	if (!r) { general_error("Failed to send ptmul_res.c2"); }
    }
    /* printf("Finished sending mask(Enc_pkS(server list) + Enc_pkS(neg client list))\n"); TTICK; */

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
