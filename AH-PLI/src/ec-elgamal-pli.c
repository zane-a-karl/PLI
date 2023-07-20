#include "../hdr/ec-elgamal-pli.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
/* static FILE *logfile; */

#define TSTART printf("Starting the clock\n"); clock_gettime(CLOCK_MONOTONIC, &t1);
#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2); sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; fprintf(stdout/* logfile */,"Line:%5d, Time = %f\n",__LINE__,sec);

int
server_run_ec_elgamal_pli (int                  new_fd,
			   enum HomomorphismType htype,
			   char              *filename)
{
    TSTART;
    int r;
    int nid;
    int num_entries = 0;
    EcGamalKeys server_keys;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    /* uint64_t *plain; */
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    // Generate Keys
    printf("Started generating server keys\n"); TTICK;
    r = generate_ec_elgamal_keys(&server_keys);
    if (!r) { perror("Failed to gen EG keys"); return FAILURE; }
    printf("Finished generating server keys\n\n"); TTICK;

    // Parse number of list entries from <filename>
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { perror("Failed to parse file for number of list entries"); return FAILURE; }

    // Parse server list entries from <filename>
    /* plain = calloc(num_entries, sizeof(uint64_t)); */
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!bn_plain[i]) { r = 0; perror("Failed to alloc bn_plain"); }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    /* r = generate_list_entries(&plain, num_entries); */
    if (!r) { perror("Failed to parse file for list entries"); return FAILURE; }
    printf("parsed server list\n");

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
    printf("Started sending server pk\n"); TTICK;
    // 1st: the NID of group
    nid = EC_GROUP_get_curve_name(server_keys.pk->group);
    r = send_msg(new_fd, &nid, "server: sent server NID group =", Integer);
    if (!r) { perror("Failed to send \"NID group\""); return FAILURE; }
    // 2nd: the order
    r = send_msg(new_fd, server_keys.pk->order, "server: sent server order =", Bignum);
    if (!r) { perror("Failed to send \"order\""); return FAILURE; }
    // 3rd: the generator
    r = send_msg(new_fd, server_keys.pk->generator, "server: sent server generator =",
		  Ecpoint, server_keys.pk->group);
    if (!r) { perror("Failed to send \"generator\""); return FAILURE; }
    // 4th: the point
    r = send_msg(new_fd, server_keys.pk->point, "server: sent server point  =",
		  Ecpoint, server_keys.pk->group);
    if (!r) { perror("Failed to send \"point\""); return FAILURE; }
    printf("Finished sending server pk\n\n"); TTICK;

    // Encrypt server list entries and send them to client
    // [1, 2, 24]
    printf("Started sending Enc_pkS(server list)\n"); TTICK;
    /* bn_plain = calloc(num_entries, sizeof(*bn_plain)); */
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	/* bn_plain[i] = BN_new(); */
	/* r = BN_set_word(bn_plain[i], plain[i]); */
	/* if (!r) { perror("Failed to set ptxt2bn"); return FAILURE; } */
	if (htype == AH) {
	    r = ah_ec_elgamal_encrypt(&server_cipher[i],
				       server_keys.pk,
				       bn_plain[i]);
	} else {
	    r = mh_ec_elgamal_encrypt(&server_cipher[i],
				       server_keys.pk,
				       bn_plain[i]);
	}
	if (!r) { perror("Failed to encrypt server plaintext"); return FAILURE; }
	// Send C1
	r = send_msg(new_fd, server_cipher[i].c1,
		      "server: sent server_cipher.c1",
		      Ecpoint, server_keys.pk->group);
	if (!r) { perror("Failed to send server_cipher.c1"); return FAILURE; }
	// Send C2
	r = send_msg(new_fd, server_cipher[i].c2,
		      "server: sent server_cipher.c2",
		      Ecpoint, server_keys.pk->group);
	if (!r) { perror("Failed to send server_cipher.c2"); return FAILURE; }
    }
    printf("Finished sending Enc_pkS(server list)\n\n"); TTICK;

    // Recv exp_res entries from client
    printf("Started receiving mask(Enc_pkS(server list) * Enc_pkS(inv client list))\n"); TTICK;
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	// Recv C1
	client_cipher[i].c1 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c1,
		      "server: recv client_cipher.c1",
		      Ecpoint, server_keys.pk->group);
	if (!r) { perror("Failed to recv client_cipher.c1"); return FAILURE; }
	// Recv C2
	client_cipher[i].c2 = EC_POINT_new(server_keys.pk->group);
	r = recv_msg(new_fd, &client_cipher[i].c2,
		      "server: recv client_cipher.c2",
		      Ecpoint, server_keys.pk->group);
	if (!r) { perror("Failed to recv client_cipher.c2"); return FAILURE; }
    }
    printf("Finished receiving masked Enc_pkS(server list) + Enc_pkS(inv client list)\n\n"); TTICK;

    // Skip decryption and just check c2 == c1*sk
    printf("Started pli ciphertext comparison\n"); TTICK;
    for (int i=0; i<num_entries; i++) {
	printf("Check#%i -> ", i);
	if (htype == AH) {
	    r = ec_elgamal_skip_dlog_check_is_at_infinity(server_keys, client_cipher[i]);
	} else {
	    r = ec_elgamal_skip_decrypt_check_equality(server_keys, client_cipher[i]);
	}
	if(!r) { perror("Failed skip decrypt/dlog check"); return FAILURE; }
    }
    printf("Finished pli ciphertext comparison\n\n"); TTICK;
    printf("Total bytes sent during protocol = %" PRIu64 "\n", total_bytes);

    EC_GROUP_free(server_keys.pk->group);
    BN_free(server_keys.pk->order);
    EC_POINT_free(server_keys.pk->generator);
    EC_POINT_free(server_keys.pk->point);
    BN_free(server_keys.pk->p);
    BN_free(server_keys.pk->a);
    BN_free(server_keys.pk->b);
    free(server_keys.pk);
    BN_free(server_keys.sk);
    /* free(plain); */
    for (int i=0; i<num_entries; i++) {
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
    close(new_fd);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
client_run_ec_elgamal_pli (int                  sockfd,
			   enum HomomorphismType htype,
			   char *             filename)
{
    TSTART;
    int r;
    int num_entries = 0;
    int nid = 0;
    EcGamalPk server_pk;
    EcGamalCiphertext *server_cipher;
    EcGamalCiphertext *client_cipher;
    /* uint64_t *plain; */
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    // Parse number of list entries from <filename>
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { perror("Failed to parse file for number of list entries"); return FAILURE; }

    // Receive server pk via socket
    printf("Started receiving server pk\n"); TTICK;
    // 1st: the NID of group
	r = recv_msg(sockfd, (void *)&nid,
		  "client: received server group nid   = ",
		      Integer);
    if (!r) { perror("Failed to recv server pk group"); return FAILURE; }
    server_pk.group = EC_GROUP_new_by_curve_name(nid);
    // 2nd: the order
    server_pk.order = BN_new();
    r = recv_msg(sockfd, (void *)&server_pk.order,
		  "client: received server order   = ",
		  Bignum);
    if (!r) { perror("Failed to recv server pk order"); return FAILURE; }
    // 3rd: the generator
    server_pk.generator = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.generator,
		  "client: received server generator   = ",
		  Ecpoint, server_pk.group);
    if (!r) { perror("Failed to recv server pk generator"); return FAILURE; }
    // 4th: the point
    server_pk.point = EC_POINT_new(server_pk.group);
    r = recv_msg(sockfd, (void *)&server_pk.point,
		  "client: received server point   = ",
		  Ecpoint, server_pk.group);
    if (!r) { perror("Failed to recv server pk point"); return FAILURE; }
    // 5th: the parameters p, a, and b
    server_pk.p = BN_new();
    server_pk.a = BN_new();
    server_pk.b = BN_new();
    r = EC_GROUP_get_curve(server_pk.group, server_pk.p, server_pk.a, server_pk.b, ctx);
    if (!r) { perror("Failed to get curve params"); return FAILURE; }
    printf("pk.p = "); BN_print_fp(stdout, server_pk.p); printf("\n");
    printf("pk.a = "); BN_print_fp(stdout, server_pk.a); printf("\n");
    printf("pk.b = "); BN_print_fp(stdout, server_pk.b); printf("\n");
    printf("Finished receiving server pk\n"); TTICK;

    // Receive ciphertext in two sequential messages of c1 and c2
    printf("Started receiving Enc_pkS(server list)\n"); TTICK;
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	// Recv c1
	server_cipher[i].c1 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c1,
		      "client: received server_cipher.c1   = ",
		      Ecpoint, server_pk.group);
	if (!r) { perror("Failed to recv server_cipher.c1"); return FAILURE; }
	// Recv c2
	server_cipher[i].c2 = EC_POINT_new(server_pk.group);
	r = recv_msg(sockfd, &server_cipher[i].c2,
		      "client: received server_cipher.c2   = ",
		      Ecpoint, server_pk.group);
	if (!r) { perror("Failed to recv server_cipher.c2"); return FAILURE; }
    }
    printf("Finished receiving Enc_pkS(server list)\n\n"); TTICK;

    // Parse client list entries from <filename>
    // [1, 2, 3]
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    for (int i = 0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	if (!r) { perror("Failed to alloc bn_plain"); return FAILURE; }
    }
    r = parse_file_for_list_entries(bn_plain, num_entries, filename);
    /* r = generate_list_entries(&plain, num_entries); */
    if (!r) { perror("Failed to parse file for list entries"); return FAILURE; }
    printf("parsed client list\n");

    // Calculate the mult inv of the client list entries
    printf("Started computing mask(Enc_pkS(server list) * Enc_pkS(inv client list))\n"); TTICK;
    /* BIGNUM *bn_plain[num_entries]; */
    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* bn_plain[i] = BN_new(); */
	/* r = BN_set_word(bn_plain[i], plain[i]); */
	/* if (!r) { perror("Failed to set bn_plain"); return FAILURE; } */
	bn_inv_plain[i] = BN_mod_inverse(NULL, bn_plain[i], server_pk.p, ctx);
	if (!bn_inv_plain[i]) { perror("Failed to invert bn_plain"); return FAILURE; }
    }
    // Encrypt inverse of client list entries
    // under the server public key
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	if (htype == AH) {
	    r = ah_ec_elgamal_encrypt(&client_cipher[i],
				       &server_pk,
				       bn_inv_plain[i]);
	} else {
	    r = mh_ec_elgamal_encrypt(&client_cipher[i],
				       &server_pk,
				       bn_inv_plain[i]);
	}
	if (!r) { perror("Error encrypting bninvplain"); return FAILURE; }
    }

    // Add the server and client ciphertexts
    EcGamalCiphertext add_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	ec_elgamal_add(&add_res[i],
		       server_cipher[i],
		       client_cipher[i],
		       server_pk);
    }

    // Generate a random masking value
    BIGNUM *bn_rand_mask[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_rand_mask[i] = BN_new();
	r = BN_rand_range_ex(bn_rand_mask[i], server_pk.p, EC_SEC_PAR, ctx);
	if (!r) { perror("Failed to gen bn_rand_mask"); return FAILURE; }
	printf("r[%i] = ", i);
	r = BN_print_fp(stdout, bn_rand_mask[i]);
	printf("\n");
	if (!r) { perror("Failed to print bn_rand_mask"); return FAILURE; }
    }
    printf("generated random masking value\n");

    // point multiply the sum of the ciphertexts
    // by the random value 'bn_rand_mask'
    EcGamalCiphertext ptmul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	r = ec_elgamal_ptmul(&ptmul_res[i], add_res[i],
			      bn_rand_mask[i], server_pk);
	if (!r) { perror("Failed to point mul the ciphertexts"); return FAILURE; }
    }
    printf("Finished computing mask(Enc_pkS(server list) + Enc_pkS(inv client list))\n"); TTICK;

    // Send exp_res to the server
    printf("Started sending mask(Enc_pkS(server list) + Enc_pkS(inv client list))\n"); TTICK;
    for (int i = 0; i < num_entries; i++) {
	// Send c1
	r = send_msg(sockfd, ptmul_res[i].c1,
		      "client: sent ptmul_res.c1",
		      Ecpoint, server_pk.group);
	if (!r) { perror("Failed to send ptmul_res.c1"); return FAILURE; }
	// Send C2
	r = send_msg(sockfd, ptmul_res[i].c2,
		      "client: sent ptmul_res.c2",
		      Ecpoint, server_pk.group);
	if (!r) { perror("Failed to send ptmul_res.c2"); return FAILURE; }
    }
    printf("Finished sending mask(Enc_pkS(server list) + Enc_pkS(inv client list))\n"); TTICK;

    EC_GROUP_free(server_pk.group);
    BN_free(server_pk.order);
    EC_POINT_free(server_pk.generator);
    EC_POINT_free(server_pk.point);
    BN_free(server_pk.p);
    BN_free(server_pk.a);
    BN_free(server_pk.b);
    /* free(plain); */
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
    free(client_cipher);
    BN_CTX_free(ctx);
    close(sockfd);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
