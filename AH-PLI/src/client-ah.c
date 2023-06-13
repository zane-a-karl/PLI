#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/rand.h>
#include <openssl/bn.h>

#include "../hdr/utils.h"
#include "../hdr/ah-elgamal.h"
#include "../hdr/elgamal-utils.h"


#define PORT "3490"      // the port client will be connecting to
#define MAX_MSG_LEN 1024 // number of bytes in a message

int
main (int   argc,
      char *argv[])
{
    int sockfd;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *port_iter;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 2) {
	fprintf(stderr,
		"usage: ./<executable> <hostname>\n");
	exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char *hostname = argv[1];
    if ((rv = getaddrinfo(hostname, PORT, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return 1;
    }

    // loop through all the results and connect to the first we can
    for ( port_iter = servinfo; port_iter != NULL; port_iter = port_iter->ai_next ) {
	sockfd = socket(port_iter->ai_family, port_iter->ai_socktype, port_iter->ai_protocol);
	if ( sockfd == -1 ) {
	    perror("client: socket");
	    continue;
	}
	if ( connect(sockfd, port_iter->ai_addr, port_iter->ai_addrlen) == -1 ) {
	    close(sockfd);
	    perror("client: connect");
	    continue;
	}
	break;
    }

    if ( !port_iter ) {
	perror("client: failed to connect\n");
	exit(2);
    }

    inet_ntop(port_iter->ai_family,
	      get_in_addr((struct sockaddr *)port_iter->ai_addr),
	      s, sizeof s);
    printf("client: connecting to %s\n", s);
    freeaddrinfo(servinfo);

    // Start the protocol
    int r;
    const int num_entries = 3;
    unsigned char buffer[MAX_MSG_LEN];
    GamalKeys client_keys;
    GamalPk server_pk;
    GamalCiphertext server_cipher[num_entries];
    GamalCiphertext client_cipher[num_entries];
    uint64_t plain[num_entries];
    uint64_t inv_plain[num_entries];

    // Generate Keys
    r = generate_elgamal_keys(&client_keys);
    if (!r) {
	perror("Failed to gen elgamal keys");
	exit(1);
    }

    // Receive server_pk via socket
    memset(buffer, 0, MAX_MSG_LEN);
    r = recv(sockfd, buffer,
	     MAX_MSG_LEN, 0);
    if ( r  == -1 ) {
	perror("recv pk2");
	exit(1);
    }
    buffer[r] = '\0';
    printf("client: received pk2 '%s'\n", buffer);
    r = alloc_gamal_pk_mem(&server_pk);
    if (!r) {
	perror("Failed to alloc mem for pk2");
	exit(1);
    }
    server_pk.modulus = client_keys.pk->modulus;
    server_pk.generator =
	client_keys.pk->generator;
    BN_bin2bn(buffer,
	      r,
	      server_pk.mul_mask);
    if (!server_pk.mul_mask) {
	perror("Failed mulmask bin2bn");
	exit(1);
    }

    // Receive ciphertext in two sequential
    // messages of c1 and c2
    for (int i = 0; i < num_entries; i++) {
	// Recv c1
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(sockfd, buffer, MAX_MSG_LEN, 0);
	if ( r  == -1 ) {
	    perror("Failed to recv c1");
	    exit(1);
	}
	buffer[r] = '\0';
	printf("client: received c1 '%s'\n",
	       buffer);
	server_cipher[i].c1 =
	    BN_bin2bn(buffer, r, NULL);
	// Recv c2
	memset(buffer, 0, MAX_MSG_LEN);
	r = recv(sockfd, buffer, MAX_MSG_LEN, 0);
	if ( r  == -1 ) {
	    perror("Failed to recv c2");
	    exit(1);
	}
	buffer[r] = '\0';
	printf("client: received c2 '%s'\n",
	       buffer);
	server_cipher[i].c2 =
	    BN_bin2bn(buffer, r, NULL);
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
    BIGNUM *plain_bn[num_entries];
    BIGNUM *inv_plain_bn[num_entries];
    for (int i = 0; i < num_entries; i++) {
	plain_bn[i] = BN_new();
	inv_plain_bn[i] = BN_new();
	// effectively uint64_2_bn
	r = BN_set_word(plain_bn[i], plain[i]);
	if (!r) {
	    perror("Failed to set plain_bn");
	    exit(1);
	}
	BN_mod_inverse(inv_plain_bn[i],
		       plain_bn[i],
		       server_pk.modulus, ctx);
	if (!inv_plain_bn[i]) {
	    perror("Failed to invert plain_bn");
	    exit(1);
	}
    }
    // Encrypt inverse of client list entries
    // under the server public key
    for (int i = 0; i < num_entries; i++) {
	// effectively bn2uint64
	inv_plain[i] =
	    BN_get_word(inv_plain_bn[i]);
	r = ah_elgamal_encrypt(&client_cipher[i],
			       &server_pk,
			       &inv_plain[i]);
	if (!r) {
	    perror("Error encrypting inv_plain");
	    exit(1);
	}
    }

    // Multiply the server and client cipher texts
    GamalCiphertext mul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	elgamal_mul(&mul_res[i],
		    &server_cipher[i],
		    &client_cipher[i],
		    server_pk.modulus);
    }

    // Generate a random masking value
    BIGNUM *rand_exponent[num_entries];
    unsigned int rand_sec_par = 1024;
    for (int i = 0; i < num_entries; i++) {
	rand_exponent[i] = BN_new();
	r = BN_rand_range_ex(rand_exponent[i],
			     server_pk.modulus,
			     rand_sec_par, ctx);
	if (!r) {
	    perror("Failed to gen rand_exp");
	    return FAILURE;
	}
	r = BN_print_fp(stdout,
			rand_exponent[i]);
	if (!r) {
	    perror("Failed to print rand_exp");
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
    unsigned char *c1 = NULL, *c2 = NULL;
    for (int i = 0; i < num_entries; i++) {
	// Send c1
	memset(buffer, 0, MAX_MSG_LEN);
	r = BN_bn2bin(exp_res[i].c1, buffer);
	if (!r) {
	    perror("Failed to serialize exp c1");
	    exit(1);
	}
	/* memcpy(buffer, c1, MAX_MSG_LEN/\* r *\/); */
	r = send(sockfd, buffer,
		 sizeof(buffer), 0);
	if (r == -1) {
	    perror("Failed to send c1");
	    close(sockfd);
	    exit(0);
	}
	printf("client: sent C1 \'%s\', length = %d\n", buffer, r);
	// Send C2
	memset(buffer, 0, MAX_MSG_LEN);
	r = BN_bn2bin(exp_res[i].c2, c2);
	if (!r) {
	    perror("Failed to serialize exp c2");
	    exit(1);
	}
	memcpy(buffer, c2, MAX_MSG_LEN/* r */);
	r = send(sockfd, buffer,
		 sizeof(buffer), 0);
	if (r == -1) {
	    perror("Failed to send exp c2");
	    close(sockfd);
	    exit(0);
	}
	printf("client: sent c2 \'%s\', length = %d\n", buffer, r);
    }

    close(sockfd);
    BN_CTX_free(ctx);

    return 0;
}
