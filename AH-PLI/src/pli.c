#include "../hdr/pli.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
/* static FILE *logfile; */

#define TSTART printf("Starting the clock\n"); clock_gettime(CLOCK_MONOTONIC, &t1);
#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2); sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; fprintf(stdout/* logfile */,"Line:%5d, Time = %f\n",__LINE__,sec);

int
server_run_pli (int                  new_fd,
		enum HomomorphismType htype,
		char              *filename)
{
    TSTART;
    int r;
    int num_entries = 0;
    GamalKeys server_keys;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    uint64_t *plain;
    BIGNUM **bn_plain;
    BN_CTX *ctx = BN_CTX_new();

    // Generate Keys
    printf("Started generating server keys\n"); TTICK;
    r = generate_elgamal_keys(&server_keys);
    if (!r) {
	perror("Failed to gen EG keys");
	return FAILURE;
    }
    printf("Finished generating server keys\n\n"); TTICK;

    // Parse number of list entries from <filename>
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) {
	perror("Failed to parse file for number of list entries");
	close(new_fd);
	return FAILURE;
    }

    // Parse server list entries from <filename>
    plain = calloc(num_entries, sizeof(uint64_t));
    r = parse_file_for_list_entries(&plain, num_entries, filename);
    if (!r) {
	perror("Failed to parse file for list entries");
	close(new_fd);
	return FAILURE;
    }
    /* r = generate_list_entries(&plain, num_entries); */
    printf("parsed server list\n");

    // Send server pk to client
    printf("Started sending server pk\n"); TTICK;
    // 1st: the modulus
    r = send_bn_msg(new_fd, server_keys.pk->modulus,
		    "server: sent server modulus   =");
    if (!r) {
	perror("Failed to send bn message \"modulus\"");
	close(new_fd);
	return FAILURE;
    }
    // 2nd: the generator
    r = send_bn_msg(new_fd, server_keys.pk->generator,
		    "server: sent server generator =");
    if (!r) {
	perror("Failed to send bn message \"generator\"");
	close(new_fd);
	return FAILURE;
    }
    // 3rd: the mul_mask
    r = send_bn_msg(new_fd, server_keys.pk->mul_mask,
		    "server: sent server mul_mask  =");
    if (!r) {
	perror("Failed to send bn message \"mul_mask\"");
	close(new_fd);
	return FAILURE;
    }
    printf("Finished sending server pk\n\n"); TTICK;

    // encrypt server list entries and send them to client
    printf("Started sending Enc_pkS(server list)\n"); TTICK;
    bn_plain = calloc(num_entries, sizeof(*bn_plain));
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i=0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	r = BN_set_word(bn_plain[i], plain[i]);
	if (!r) {
	    perror("Failed to set ptxt2bn");
	    return FAILURE;
	}
	if (htype == AH) {
	    r = ah_elgamal_encrypt(&server_cipher[i],
				   server_keys.pk,
				   bn_plain[i]);
	} else {
	    r = mh_elgamal_encrypt(&server_cipher[i],
				   server_keys.pk,
				   bn_plain[i]);
	}
	// Send C1
	r = send_bn_msg(new_fd, server_cipher[i].c1,
			"server: sent server_cipher.c1");
	if (!r) {
	    perror("Failed to send bn message \"server_cipher.c1\"");
	    close(new_fd);
	    return FAILURE;
	}
	// Send C2
	r = send_bn_msg(new_fd, server_cipher[i].c2,
			"server: sent server_cipher.c2");
	if (!r) {
	    perror("Failed to send bn message \"server_cipher.c2\"");
	    close(new_fd);
	    return FAILURE;
	}
    }
    printf("Finished sending Enc_pkS(server list)\n\n"); TTICK;

    // Recv exp_res entries from client
    printf("Started receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK;
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i=0; i<num_entries; i++) {
	// Recv C1
	client_cipher[i].c1 = BN_new();
	r = recv_bn_msg(new_fd, client_cipher[i].c1,
			"server: recv client_cipher.c1");
	if (!r) {
	    perror("Failed to recv bn message \"client_cipher.c1\"");
	    close(new_fd);
	    return FAILURE;
	}
	// Recv C2
	client_cipher[i].c2 = BN_new();
	r = recv_bn_msg(new_fd, client_cipher[i].c2,
			"server: recv client_cipher.c2");
	if (!r) {
	    perror("Failed to recv bn message \"client_cipher.c2\"");
	    close(new_fd);
	    return FAILURE;
	}
    }
    printf("Finished receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n\n"); TTICK;

    // Skip decryption and just check c2 == c1^sk
    printf("Started pli ciphertext comparison\n"); TTICK;
    for (int i=0; i<num_entries; i++) {
	printf("Check#%i -> ", i);
	if (htype == AH) {
	    r = ah_skip_dlog_check_is_one(&server_keys, &client_cipher[i]);
	} else {
	    r = mh_skip_decrypt_check_equality(&server_keys, &client_cipher[i]);
	}
	if(!r) {
	    perror("Failed check");
	    return FAILURE;
	}
    }
    printf("Finished pli ciphertext comparison\n\n"); TTICK;
    printf("Total bytes sent during protocol = %" PRIu64 "\n", total_bytes);

    BN_free(server_keys.pk->modulus);
    BN_free(server_keys.pk->generator);
    BN_free(server_keys.pk->mul_mask);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    free(plain);
    for (int i=0; i<num_entries; i++) {
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
    return SUCCESS;
}

int
client_run_pli (int                  sockfd,
		enum HomomorphismType htype,
		char *             filename)
{
    TSTART;
    int r;
    int num_entries = 0;
    GamalKeys client_keys;
    GamalPk server_pk;
    GamalCiphertext *server_cipher;
    GamalCiphertext *client_cipher;
    uint64_t *plain;

    // Generate Keys
    printf("Started generating client keys\n"); TTICK;
    r = generate_elgamal_keys(&client_keys);
    if (!r) {
	perror("Failed to gen elgamal keys");
	close(sockfd);
	return FAILURE;
    }
    printf("Finished generating client keys\n\n"); TTICK;

    // Parse number of list entries from <filename>
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) {
	perror("Failed to parse file for number of list entries");
	close(sockfd);
	return FAILURE;
    }

    // Receive server_pk via socket
    printf("Started receiving server pk\n"); TTICK;
    // 1st: the modulus
    server_pk.modulus = BN_new();
    r = recv_bn_msg(sockfd, server_pk.modulus,
		    "client: received server modulus   = ");
    if (!r) {
	perror("Failed to recv bn message \"server modulus\"");
	close(sockfd);
	return FAILURE;
    }

    // 2nd: the generator
    server_pk.generator = BN_new();
    r = recv_bn_msg(sockfd, server_pk.generator,
		    "client: received server generator   = ");
    if (!r) {
	perror("Failed to recv bn message \"server generator\"");
	close(sockfd);
	return FAILURE;
    }
    // 3rd: the mul_mask
    server_pk.mul_mask = BN_new();
    r = recv_bn_msg(sockfd, server_pk.mul_mask,
		    "client: received server mul_mask   = ");
    if (!r) {
	perror("Failed to recv bn message \"server mul_mask\"");
	close(sockfd);
	return FAILURE;
    }
    printf("Finished receiving server pk\n"); TTICK;

    // Receive ciphertext in two sequential
    // messages of c1 and c2
    printf("Started receiving Enc_pkS(server list)\n"); TTICK;
    server_cipher = calloc(num_entries, sizeof(*server_cipher));
    for (int i = 0; i < num_entries; i++) {
	// Recv c1
	server_cipher[i].c1 = BN_new();
	r = recv_bn_msg(sockfd, server_cipher[i].c1,
			"client: received server_cipher.c1   = ");
	if (!r) {
	    perror("Failed to recv bn message \"server_cipher.c1\"");
	    close(sockfd);
	    return FAILURE;
	}
	// Recv c2
	server_cipher[i].c2 = BN_new();
	r = recv_bn_msg(sockfd, server_cipher[i].c2,
			"client: received server_cipher.c2   = ");
	if (!r) {
	    perror("Failed to recv bn message \"server_cipher.c2\"");
	    close(sockfd);
	    return FAILURE;
	}
    }
    printf("Finished receiving Enc_pkS(server list)\n\n"); TTICK;

    // Parse client list entries from <filename>
    plain = calloc(num_entries, sizeof(uint64_t));
    r = parse_file_for_list_entries(&plain, num_entries, filename);
    if (!r) {
	perror("Failed to parse file for list entries");
	close(sockfd);
	return FAILURE;
    }
    /* r = generate_list_entries(&plain, num_entries); */
    printf("parsed client list\n");

    // Calculate the mult inv of the client list
    // entries
    printf("Started computing mask Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_plain[num_entries];
    BIGNUM *bn_inv_plain[num_entries];
    for (int i = 0; i < num_entries; i++) {
	bn_plain[i] = BN_new();
	// effectively uint64_2_bn
	r = BN_set_word(bn_plain[i], plain[i]);
	if (!r) {
	    perror("Failed to set bn_plain");
	    close(sockfd);
	    return FAILURE;
	}
	bn_inv_plain[i] =
	    BN_mod_inverse(NULL, bn_plain[i],
			   server_pk.modulus,
			   ctx);
	if (!bn_inv_plain[i]) {
	    perror("Failed to invert bn_plain");
	    close(sockfd);
	    return FAILURE;
	}
    }
    // Encrypt inverse of client list entries
    // under the server public key
    client_cipher = calloc(num_entries, sizeof(*client_cipher));
    for (int i = 0; i < num_entries; i++) {
	if (htype == AH) {
	    r = ah_elgamal_encrypt(&client_cipher[i],
				   &server_pk,
				   bn_inv_plain[i]);
	} else {
	    r = mh_elgamal_encrypt(&client_cipher[i],
				   &server_pk,
				   bn_inv_plain[i]);
	}
	if (!r) {
	    perror("Error encrypting bninvplain");
	    close(sockfd);
	    return FAILURE;
	}
    }

    // Multiply the server and client
    // cipher texts
    GamalCiphertext mul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	elgamal_mul(&mul_res[i],
		    &server_cipher[i],
		    &client_cipher[i],
		    server_pk.modulus);
    }

    // Generate a random masking value
    BIGNUM *rand_exponent[num_entries];
    unsigned int sec_par = 49;
    for (int i = 0; i < num_entries; i++) {
	rand_exponent[i] = BN_new();
	r = BN_rand_range_ex(rand_exponent[i],
			     server_pk.modulus,
			     sec_par, ctx);
	if (!r) {
	    perror("Failed to gen rand_exp");
	    close(sockfd);
	    return FAILURE;
	}
	printf("r[%i] = ", i);
	r = BN_print_fp(stdout,rand_exponent[i]);
	printf("\n");
	if (!r) {
	    perror("Failed to print rand_exp");
	    close(sockfd);
	    return FAILURE;
	}
    }
    printf("generated random masking value\n");

    // Raise product of ciphertext to
    // the random value 'rand_exponent'
    GamalCiphertext exp_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	elgamal_exp(&exp_res[i], &mul_res[i],
		    rand_exponent[i],
		    server_pk.modulus);
    }
    printf("Finished computing mask Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK;

    // Send exp_res to the server
    printf("Started sending mask Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK;
    for (int i = 0; i < num_entries; i++) {
	// Send c1
	r = send_bn_msg(sockfd, exp_res[i].c1,
			"client: sent exp_res.c1");
	if (!r) {
	    perror("Failed to send bn message \"exp_res.c1\"");
	    close(sockfd);
	    return FAILURE;
	}
	// Send C2
	r = send_bn_msg(sockfd, exp_res[i].c2,
			"client: sent exp_res.c2");
	if (!r) {
	    perror("Failed to send bn message \"exp_res.c2\"");
	    close(sockfd);
	    return FAILURE;
	}
    }
    printf("Finished sending mask Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK;

    close(sockfd);
    BN_free(client_keys.pk->modulus);
    BN_free(client_keys.pk->generator);
    BN_free(client_keys.pk->mul_mask);
    free(client_keys.pk);
    BN_free(client_keys.sk->secret);
    free(client_keys.sk);
    BN_free(server_pk.modulus);
    BN_free(server_pk.generator);
    BN_free(server_pk.mul_mask);
    free(plain);
    for (int i = 0; i < num_entries; i++) {
	BN_free(bn_plain[i]);
	BN_free(bn_inv_plain[i]);
	BN_free(rand_exponent[i]);
	BN_free(exp_res[i].c1);
	BN_free(exp_res[i].c2);
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
    }
    free(server_cipher);
    free(client_cipher);
    BN_CTX_free(ctx);
    return SUCCESS;
}
