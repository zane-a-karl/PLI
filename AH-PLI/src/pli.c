#include "../hdr/pli.h"

int
server_run_pli (int                  new_fd,
		enum HomomorphismType htype)
{
    int r;
    const int num_entries = 3;
    char *buffer;
    char *hex;
    GamalKeys server_keys;
    GamalCiphertext server_cipher[num_entries];
    GamalCiphertext client_cipher[num_entries];
    uint64_t plain[num_entries];
    BIGNUM *bn_recovered[num_entries];
    BIGNUM *bn_plain[num_entries];
    BN_CTX *ctx = BN_CTX_new();

    buffer = calloc(MAX_MSG_LEN,sizeof(char));

    // Generate Keys
    r = generate_elgamal_keys(&server_keys);
    if (!r) {
	perror("Failed to gen EG keys");
	return FAILURE;
    }

    // Generate server list entries
    // i.e. {1, 2, 4}
    /* srand (time(NULL)); */
    plain[0] = (uint64_t)1;
    plain[1] = (uint64_t)2;
    plain[2] = (uint64_t)4;
    for (int i=0; i<num_entries; i++) {
	/* plain[i]  = */
	/*     ((uint64_t) rand()) * i; */
	/* plain[i] %= ((1ULL) << 32); */
	/* plain[i] = */
	/*     (uint64_t)i + 1ULL; */
	printf("plain[%i] = %" PRIu64 "\n",
	       i, plain[i]);
    }
    printf("generated server list\n");

    // send pk2 to client
    // 1st: the modulus
    memset(buffer, 0, MAX_MSG_LEN);
    hex = BN_bn2hex(server_keys.pk->modulus);
    if (!hex) {
	close(new_fd);
	perror("Error bn2hex pk2 modulus");
	return FAILURE;
    }
    r = strlcpy(buffer, hex,
		strnlen(hex,MAX_MSG_LEN));
    if (!r) {
	close(new_fd);
	perror("Error strlcpy hex2buf");
	return FAILURE;
    }
    free(hex);
    sleep(1);
    r = send(new_fd, buffer,
	     strnlen(buffer,MAX_MSG_LEN),
	     0);
    if (r == -1) {
	perror("Failed to send modulus");
	close(new_fd);
	return FAILURE;
    }
    printf("server: sent pk2 modulus   =");
    printf(" %s\n", buffer);
    // 2nd: the generator
    memset(buffer, 0, MAX_MSG_LEN);
    hex = BN_bn2hex(server_keys.pk->generator);
    if (!hex) {
	close(new_fd);
	perror("Error bn2hex pk2 gen");
	return FAILURE;
    }
    r = strlcpy(buffer, hex,
		strnlen(hex, MAX_MSG_LEN));
    if (!r) {
	close(new_fd);
	perror("Error strlcpy hex2buffer");
	return FAILURE;
    }
    free(hex);
    sleep(1);
    r = send(new_fd, buffer,
	     strnlen(buffer, MAX_MSG_LEN),
	     0);
    if (r == -1) {
	perror("Failed to send generator");
	close(new_fd);
	return FAILURE;
    }
    printf("server: sent pk2 generator =");
    printf(" %s\n", buffer);
    // 3rd: the mul_mask
    memset(buffer, 0, MAX_MSG_LEN);
    hex = BN_bn2hex(server_keys.pk->mul_mask);
    if (!hex) {
	close(new_fd);
	perror("Error bn2hex pk2 mask");
	return FAILURE;
    }
    r = strlcpy(buffer, hex,
		strnlen(hex, MAX_MSG_LEN));
    if (!r) {
	close(new_fd);
	perror("Error strlcpy hex2buffer");
	return FAILURE;
    }
    free(hex);
    sleep(1);
    r = send(new_fd, buffer,
	     strnlen(buffer, MAX_MSG_LEN),
	     0);
    if (r == -1) {
	perror("Failed to send mul_mask");
	close(new_fd);
	return FAILURE;
    }
    printf("server: sent pk2 mul_mask  =");
    printf(" %s\n", buffer);

    // encrypt server list entries and send them to client
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
	memset(buffer, 0, MAX_MSG_LEN);
	hex = BN_bn2hex(server_cipher[i].c1);
	if (!hex) {
	    close(new_fd);
	    perror("Error bn2hex c1");
	    return FAILURE;
	}
	r = strlcpy(buffer, hex,
		    strnlen(hex, MAX_MSG_LEN));
	if (!r) {
	    close(new_fd);
	    perror("Error strlcpy hex2buffer");
	    return FAILURE;
	}
	free(hex);
	sleep(1);
	r = send(new_fd, buffer,
		 strnlen(buffer,
			 MAX_MSG_LEN), 0);
	if (r == -1) {
	    perror("send C1");
	    close(new_fd);
	    return FAILURE;
	}
	printf("server: sent c1 \'%s\'\n",
	       buffer);
	// Send C2
	memset(buffer, 0, MAX_MSG_LEN);
	hex = BN_bn2hex(server_cipher[i].c2);
	if (!hex) {
	    close(new_fd);
	    perror("Error bn2hex c2");
	    return FAILURE;
	}
	r = strlcpy(buffer, hex,
		    strnlen(hex, MAX_MSG_LEN));
	if (!r) {
	    close(new_fd);
	    perror("Error strlcpy hex2buffer");
	    return FAILURE;
	}
	free(hex);
	sleep(1);
	r = send(new_fd, buffer,
		 strnlen(buffer,
			 MAX_MSG_LEN), 0);
	if (r == -1) {
	    perror("failed to send C2");
	    close(new_fd);
	    return FAILURE;
	}
	printf("server: sent c2 \'%s\'\n",
	       buffer);
    }

    // Recv exp_res entries from client
    for (int i=0; i<num_entries; i++) {
	// Recv C1
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(new_fd, buffer,
		 MAX_MSG_LEN, 0);
	if ( r  == -1 ) {
	    perror("failed to recv C1");
	    return FAILURE;
	}
	buffer[r] = '\0';
	printf("server: recv c1 '%s'\n",
	       buffer);
	client_cipher[i].c1 = BN_new();
	r = BN_hex2bn(&client_cipher[i].c1,
		      buffer);
	if (!r) {
	    perror("Failed c1 hex2bn");
	    close(new_fd);
	    return FAILURE;
	}
	// Recv C2
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(new_fd, buffer,
		 MAX_MSG_LEN, 0);
	if ( r  == -1 ) {
	    perror("recv C2");
	    return FAILURE;
	}
	buffer[r] = '\0';
	printf("server: recv c2 '%s'\n",
	       buffer);
	client_cipher[i].c2 = BN_new();
	r = BN_hex2bn(&client_cipher[i].c2,
		      buffer);
	if (!r) {
	    perror("Failed c2 hex2bn");
	    close(new_fd);
	    return FAILURE;
	}
    }

    // Decrypt the client ciphertext
    for (int i=0; i<num_entries; i++) {
	bn_recovered[i] = BN_new();
	if (htype == AH) {
	    r = ah_elgamal_decrypt(bn_recovered[i],
				   &server_keys,
				   &client_cipher[i]);
	} else {
	    r = mh_elgamal_decrypt(bn_recovered[i],
				   &server_keys,
				   &client_cipher[i]);
	}	
	if(!r) {
	    perror("Failed recvr plain");
	    return FAILURE;
	}
    }
    printf("Successfully decrypted\n");
    for (int i=0; i<num_entries; i++) {
	/* printf("recovered_plain[%i] = %" PRIu64 "\n", i, recovered_plain[i]); */
	printf("recovered_plain[%i] = ", i);
	r = BN_print_fp(stdout, bn_recovered[i]);
	if (BN_is_one(bn_recovered[i])) {
	    printf("Found a match!");
	}
	printf("\n");
    }

    BN_free(server_keys.pk->modulus);
    BN_free(server_keys.pk->generator);
    BN_free(server_keys.pk->mul_mask);
    free(server_keys.pk);
    BN_free(server_keys.sk->secret);
    free(server_keys.sk);
    for (int i=0; i<num_entries; i++) {
	BN_free(client_cipher[i].c1);
	BN_free(client_cipher[i].c2);
	BN_free(server_cipher[i].c1);
	BN_free(server_cipher[i].c2);
	BN_free(bn_plain[i]);
	BN_free(bn_recovered[i]);
    }
    free(buffer);
    BN_CTX_free(ctx);
    return SUCCESS;
}

int
client_run_pli (int                  sockfd,
		enum HomomorphismType htype)
{
    int r;
    const int num_entries = 3;
    char *buffer;
    GamalKeys client_keys;
    GamalPk server_pk;
    GamalCiphertext server_cipher[num_entries];
    GamalCiphertext client_cipher[num_entries];
    uint64_t plain[num_entries];

    buffer = calloc(MAX_MSG_LEN, sizeof(char));

    // Generate Keys
    r = generate_elgamal_keys(&client_keys);
    if (!r) {
	perror("Failed to gen elgamal keys");
	close(sockfd);
	return FAILURE;
    }

    // Receive server_pk via socket
    // 1st: the modulus
    memset(buffer, 0, MAX_MSG_LEN);
    r = recv(sockfd, buffer, MAX_MSG_LEN-1, 0);
    if ( r  == -1 ) {
	perror("recv pk2");
	close(sockfd);
	return FAILURE;
    }
    buffer[r] = '\0';
    printf("client: received modulus   = ");
    printf("%s\n", buffer);
    server_pk.modulus = BN_new();
    r = BN_hex2bn(&server_pk.modulus, buffer);
    if (!r) {
	perror("Failed mulmask hex2bn");
	close(sockfd);
	return FAILURE;
    }
    // 2nd: the generator
    memset(buffer, 0, MAX_MSG_LEN);
    r = recv(sockfd, buffer, MAX_MSG_LEN-1, 0);
    if ( r  == -1 ) {
	perror("recv pk2");
	close(sockfd);
	return FAILURE;
    }
    buffer[r] = '\0';
    printf("client: received generator = ");
    printf("%s\n", buffer);
    server_pk.generator = BN_new();
    r = BN_hex2bn(&server_pk.generator, buffer);
    if (!r) {
	perror("Failed mulmask hex2bn");
	close(sockfd);
	return FAILURE;
    }
    // 3rd: the mul_mask
    memset(buffer, 0, MAX_MSG_LEN);
    r = recv(sockfd, buffer, MAX_MSG_LEN-1, 0);
    if ( r  == -1 ) {
	perror("recv pk2");
	close(sockfd);
	return FAILURE;
    }
    buffer[r] = '\0';
    printf("client: received mul_mask  = ");
    printf("%s\n", buffer);
    server_pk.mul_mask = BN_new();
    r = BN_hex2bn(&server_pk.mul_mask, buffer);
    if (!r) {
	perror("Failed mulmask hex2bn");
	close(sockfd);
	return FAILURE;
    }

    // Receive ciphertext in two sequential
    // messages of c1 and c2
    for (int i = 0; i < num_entries; i++) {
	// Recv c1
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(sockfd, buffer,MAX_MSG_LEN-1,0);
	if ( r  == -1 ) {
	    perror("Failed to recv c1");
	    close(sockfd);
	    return FAILURE;
	}
	buffer[r] = '\0';
	printf("client: received c1 '%s'\n",
	       buffer);
	server_cipher[i].c1 = BN_new();
	r = BN_hex2bn(&server_cipher[i].c1,
		      buffer);
	if (!r) {
	    perror("Failed to hex2bn c1");
	    close(sockfd);
	    return FAILURE;
	}
	// Recv c2
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(sockfd, buffer,MAX_MSG_LEN-1,0);
	if ( r  == -1 ) {
	    perror("Failed to recv c2");
	    close(sockfd);
	    return FAILURE;
	}
	buffer[r] = '\0';
	printf("client: received c2 '%s'\n",
	       buffer);
	server_cipher[i].c2 = BN_new();
	r = BN_hex2bn(&server_cipher[i].c2,
		      buffer);
	if (!r) {
	    perror("Failed to hex2bn c1");
	    close(sockfd);
	    return FAILURE;
	}
    }

    // Generate client list entries
    // i.e. {1, 2, 3}
    /* srand (time(NULL)); */
    for (int i = 0; i < num_entries; i++) {
	//plain[i]  = ((uint64_t) rand()) * i;
	//plain[i] %= ((1ULL) << 32);
	plain[i] = (uint64_t)i + (uint64_t)1ULL;
	printf("plain[%i] = %" PRIu64 "\n",
	       i, plain[i]);
    }
    printf("generated client list\n");

    // Calculate the mult inv of the client list
    // entries
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
	printf("bn_plain: ");
	r = BN_print_fp(stdout, bn_plain[i]);
	printf("\n");
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
    for (int i = 0; i < num_entries; i++) {
	printf("bn_inv_plain: ");
	r = BN_print_fp(stdout, bn_inv_plain[i]);
	printf("\n");
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

    // Send exp_res to the server
    char *hex;
    for (int i = 0; i < num_entries; i++) {
	// Send c1
	memset(buffer, 0, MAX_MSG_LEN);
        hex = BN_bn2hex(exp_res[i].c1);
	if (!hex) {
	    perror("Error bn2hex exp.c1");
	    close(sockfd);
	    return FAILURE;
	}
	r = strlcpy(buffer, hex,
		    strnlen(hex, MAX_MSG_LEN));
	if (!r) {
	    perror("Error strlcpy hex2buffer");
	    close(sockfd);
	    return FAILURE;
	}
	free(hex);
	sleep(1);
	r = send(sockfd, buffer,
		 strnlen(buffer, MAX_MSG_LEN),
		 0);
	if (r == -1) {
	    perror("Failed to send c1");
	    close(sockfd);
	    return FAILURE;
	}
	printf("client(%d): ", r);
	printf("sent c1 \'%s\'\n", buffer);
	// Send C2
	memset(buffer, 0, MAX_MSG_LEN);
	hex = BN_bn2hex(exp_res[i].c2);
	if (!hex) {
	    perror("Error bn2hex exp.c2");
	    close(sockfd);
	    return FAILURE;
	}
	r = strlcpy(buffer, hex,
		    strnlen(hex, MAX_MSG_LEN));
	if (!r) {
	    perror("Error strlcpy hex2buffer");
	    close(sockfd);
	    return FAILURE;
	}
	free(hex);
	sleep(1);
	r = send(sockfd, buffer,
		 strnlen(buffer, MAX_MSG_LEN),
		 0);
	if (r == -1) {
	    perror("Failed to send exp c2");
	    close(sockfd);
	    return FAILURE;
	}
	printf("client(%d): ", r);
	printf("sent c2 \'%s\'\n",
	       buffer);
    }

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
    free(buffer);
    BN_CTX_free(ctx);
    return SUCCESS;
}
