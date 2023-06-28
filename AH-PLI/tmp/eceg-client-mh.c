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

#include <ecelgamal.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#define PORT "3490"      // the port client will be connecting to
#define MAX_MSG_LEN 1024 // number of bytes in a message


int
gamal_mul(gamal_ciphertext_t *res,
	  gamal_ciphertext_t cipher1,
	  gamal_ciphertext_t cipher2,
	  const EC_GROUP *group,
	  const BIGNUM *prime)
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *c1c1_x = BN_new();
    BIGNUM *c1c1_y = BN_new();
    BIGNUM *c1c2_x = BN_new();
    BIGNUM *c1c2_y = BN_new();

    BIGNUM *c2c1_x = BN_new();
    BIGNUM *c2c1_y = BN_new();
    BIGNUM *c2c2_x = BN_new();
    BIGNUM *c2c2_y = BN_new();

    BIGNUM *c1c1_c2c1_x = BN_new();
    BIGNUM *c1c1_c2c1_y = BN_new();
    BIGNUM *c1c2_c2c2_x = BN_new();
    BIGNUM *c1c2_c2c2_y = BN_new();

    // Convert points to affine coordinates
    if ( !EC_POINT_get_affine_coordinates(group, cipher1->C1, c1c1_x, c1c1_y, ctx) ) {
	perror("Error getting affine coordinates of cipher1->C1");
    }
    if ( !EC_POINT_get_affine_coordinates(group, cipher1->C2, c1c2_x, c1c2_y, ctx) ) {
	perror("Error getting affine coordinates of cipher1->C2");
    }
    if ( !EC_POINT_get_affine_coordinates(group, cipher2->C1, c2c1_x, c2c1_y, ctx) ) {
	perror("Error getting affine coordinates of cipher2->C1");
    }
    if ( !EC_POINT_get_affine_coordinates(group, cipher2->C2, c2c2_x, c2c2_y, ctx) ) {
	perror("Error getting affine coordinates of cipher2->C2");
    }

    // Perform point multiplication using affine coordinates
    if ( !BN_mod_mul(c1c1_c2c1_x, c1c1_x, c2c1_x, prime, ctx) ) {
	perror("Error mod_mul'ing c1c1 and c2c1");
    }
    if ( !BN_mod_mul(c1c1_c2c1_y, c1c1_y, c2c1_y, prime, ctx) ) {
	perror("Error mod_mul'ing c1c1 and c2c1");
    }
    if ( !BN_mod_mul(c1c2_c2c2_x, c1c2_x, c2c2_x, prime, ctx) ) {
	perror("Error mod_mul'ing c1c2 and c2c2");
    }
    if ( !BN_mod_mul(c1c2_c2c2_y, c1c2_y, c2c2_y, prime, ctx) ) {
	perror("Error mod_mul'ing c1c2 and c2c2");
    }

    // Reconstruct the resulting point
    EC_POINT *res_c1 = EC_POINT_new(group);
    EC_POINT *res_c2 = EC_POINT_new(group);
    if ( !EC_POINT_set_affine_coordinates(group, res_c2, c1c2_c2c2_x, c1c2_c2c2_y, ctx) ) {
	perror("Error setting affine coordinates of res->C2");
    }
    if ( !EC_POINT_set_affine_coordinates(group, res_c1, c1c1_c2c1_x, c1c1_c2c1_y, ctx) ) {
	perror("Error setting affine coordinates of res->C1");
    }

    BN_free(c1c1_x);
    BN_free(c1c1_y);
    BN_free(c1c2_x);
    BN_free(c1c2_y);

    BN_free(c2c1_x);
    BN_free(c2c1_y);
    BN_free(c2c2_x);
    BN_free(c2c2_y);

    BN_free(c1c1_c2c1_x);
    BN_free(c1c1_c2c1_y);
    BN_free(c1c2_c2c2_x);
    BN_free(c1c2_c2c2_y);

    BN_CTX_free(ctx);
    return 0;
}


uint8_t *
uint64_to_bytes (uint64_t input)
{
    uint8_t *bytes = calloc(8, sizeof(uint8_t));
    if (bytes == NULL) {
	perror("Failed to calloc bytes");
	exit(1);
    }
    bytes[0] = ( (input >> (7*8)) & 0x00000000000000FFLLU );
    bytes[1] = ( (input >> (6*8)) & 0x00000000000000FFLLU );
    bytes[2] = ( (input >> (5*8)) & 0x00000000000000FFLLU );
    bytes[3] = ( (input >> (4*8)) & 0x00000000000000FFLLU );
    bytes[4] = ( (input >> (3*8)) & 0x00000000000000FFLLU );
    bytes[5] = ( (input >> (2*8)) & 0x00000000000000FFLLU );
    bytes[6] = ( (input >> (1*8)) & 0x00000000000000FFLLU );
    bytes[7] = ( (input >> (0*8)) & 0x00000000000000FFLLU );
    return bytes;
}

uint64_t
bytes_to_uint64 (uint8_t *bytes)
{
    uint64_t t = (uint64_t) 0;
    t |= ( ((uint64_t)bytes[0] << (7*8)) & 0xFF00000000000000 );
    t |= ( ((uint64_t)bytes[1] << (6*8)) & 0x00FF000000000000 );
    t |= ( ((uint64_t)bytes[2] << (5*8)) & 0x0000FF0000000000 );
    t |= ( ((uint64_t)bytes[3] << (4*8)) & 0x000000FF00000000 );
    t |= ( ((uint64_t)bytes[4] << (3*8)) & 0x00000000FF000000 );
    t |= ( ((uint64_t)bytes[5] << (2*8)) & 0x0000000000FF0000 );
    t |= ( ((uint64_t)bytes[6] << (1*8)) & 0x000000000000FF00 );
    t |= ( ((uint64_t)bytes[7] << (0*8)) & 0x00000000000000FF );
    return t;
}

char *
point_to_hex(EC_GROUP *curve_group,
	     const EC_POINT *point)
{
    BN_CTX *ctx;
    char *s;
    point_conversion_form_t form = POINT_CONVERSION_COMPRESSED;
    ctx = BN_CTX_new();
    s = EC_POINT_point2hex(curve_group, point, form, ctx);
    BN_CTX_free(ctx);
    return s;
}

EC_POINT *
hex_to_point (EC_GROUP   *curve_group,
	      const char *hex)
{
    BN_CTX *ctx;
    EC_POINT *point;
    ctx = BN_CTX_new();
    point = EC_POINT_hex2point(curve_group, hex, NULL, ctx);
    BN_CTX_free(ctx);
    return point;
}

// get sockaddr, IPv4 or IPv6:
void *
get_in_addr (struct sockaddr *sa)
{
    if ( sa->sa_family == AF_INET ) {
	return &( ((struct sockaddr_in*)sa)->sin_addr );
    }
    return &( ((struct sockaddr_in6*)sa)->sin6_addr );
}

int
main (int   argc,
      char *argv[])
{
    int sockfd;
    struct addrinfo hints, *servinfo, *port_iter; int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 2) {
	fprintf(stderr,"usage: ./<executable> client hostname\n");
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

    if ( port_iter == NULL ) {
	fprintf(stderr, "client: failed to connect\n");
	return 2;
    }

    inet_ntop( port_iter->ai_family, get_in_addr( (struct sockaddr *)port_iter->ai_addr ), s, sizeof (s) );
    printf("client: connecting to %s\n", s);
    freeaddrinfo(servinfo);

    // Start the protocol
    const int num_entries = 3;
    int numrecv_bytes;
    char buffer[MAX_MSG_LEN];
    gamal_key_t client_key;
    gamal_ciphertext_t server_cipher[num_entries];
    gamal_ciphertext_t client_cipher[num_entries];
    dig_t plain[num_entries], inv_plain[num_entries];
    bsgs_table_t table;
    int tablebits = 16; // got this from testing.cpp bench_elgamal
    srand (time(NULL));
    gamal_init(CURVE_256_SEC);
    EC_GROUP *group = gamal_get_current_group();
    gamal_generate_keys(client_key);
    gamal_init_bsgs_table(table, (dig_t) 1L << tablebits);

    // Receive pk2 from the server
    memset(buffer, 0, MAX_MSG_LEN);
    numrecv_bytes = recv(sockfd, buffer, MAX_MSG_LEN, 0);
    if ( numrecv_bytes  == -1 ) {
	perror("recv pk2");
	exit(1);
    }
    buffer[numrecv_bytes] = '\0';
    printf("client: received pk2 '%s'\n", buffer);
    EC_POINT *server_pk = hex_to_point(group, buffer);
    // Set up the server_key struct to all for encryption only
    gamal_key_t server_key;
    server_key->Y = server_pk;

    // Receive in two sequential messages of C1 and C2
    for (int i = 0; i < num_entries; i++) {
	// Recv C1
	memset(buffer, 0, MAX_MSG_LEN);
	numrecv_bytes = recv(sockfd, buffer, MAX_MSG_LEN, 0);
	if ( numrecv_bytes  == -1 ) {
	    perror("recv C1");
	    exit(1);
	}
	buffer[numrecv_bytes] = '\0';
	printf("client: received C1  '%s'\n", buffer);
	server_cipher[i]->C1 = hex_to_point(group, buffer);
	// Recv C2
	memset(buffer, 0, MAX_MSG_LEN);
	numrecv_bytes = recv(sockfd, buffer, MAX_MSG_LEN, 0);
	if ( numrecv_bytes  == -1 ) {
	    perror("recv C2");
	    exit(1);
	}
	buffer[numrecv_bytes] = '\0';
	printf("client: received C2  '%s'\n", buffer);
	server_cipher[i]->C2 = hex_to_point(group, buffer);
    }

    // Generate client list entries i.e. {1, 2, 3}
    for (int i = 0; i < num_entries; i++) {
	/* plain[i] = ((dig_t) rand()) * i % (((dig_t)1L) << 32); */
	plain[i] = (dig_t)i + (dig_t)1L;
	printf("plain[%i] = %" PRIu64 "\n", i, plain[i]);
    }
    printf("generated client list\n");

    // Get the EC parameters
    BIGNUM *p, *a, *b;
    BN_CTX *ctx;

    p = BN_new();
    a = BN_new();
    b = BN_new();
    ctx = BN_CTX_new();
    int get_curve_rv = EC_GROUP_get_curve(group, p, a, b, ctx);
    if ( !get_curve_rv ) {
	perror("Failed to get EC parameters");
	exit(1);
    }
    printf("p is %s\n", BN_bn2hex(p));
    printf("a is %s\n", BN_bn2hex(a));
    printf("b is %s\n", BN_bn2hex(b));

    // Generate a random masking value
    unsigned char r[8];
    RAND_bytes(r, 8);
    int masking_val = 0;
    for (int i = 0; i < 8; i++) {
	printf("%i ", r[i]);
    }
    printf("generated random masking value\n");

    // Calculate the mult inv of the client list
    // entries
    BIGNUM *plain_bn[num_entries];
    BIGNUM *inv_plain_bn[num_entries];
    for (int i = 0; i < num_entries; i++) {
	BN_set_word(plain_bn[i], plain[i]); // effectively uint64_2_bn
	inv_plain_bn[i] = BN_mod_inverse(NULL,
					 plain_bn[i],
					 p,
					 ctx);
    }
    // Encrypt inverse of client list entries
    // under the server public key
    for (int i = 0; i < num_entries; i++) {
	inv_plain[i] = BN_get_word(inv_plain_bn[i]); // effectively bn2uint64
	if ( 0 != gamal_encrypt(client_cipher[i],
				server_key,
				inv_plain[i]) ) {
	    perror("Error encrypting inv_plain");
	}
    }

    // Multiply the server and client cipher texts
    // and raise them to the random value 'r'
    gamal_ciphertext_t mul_res[num_entries];
    for (int i = 0; i < num_entries; i++) {
	gamal_mul(&(mul_res[i]), server_cipher[i], client_cipher[i], group, p);
    }
    // NOT SURE HOW TO DO THIS RIGHT NOW SO I'LL JUST LEAVE OFF 'r'
    /* gamal_ciphertext_t exp_res[num_entries]; */
    /* for (int i = 0; i < num_entries; i++) { */
    /* 	gamal_exp(exp_res[i], mul_res[i], r, group); */
    /* } */

    // Send exp_res to the server
    int send_rv;
    char *c1, *c2;
    for (int i = 0; i < num_entries; i++) {
	// Send C1
	memset(buffer, 0, MAX_MSG_LEN);
	c1 = point_to_hex(group, mul_res[i]->C1);
	memcpy(buffer, c1, MAX_MSG_LEN);
	send_rv = send(sockfd, buffer, sizeof(buffer), 0);
	if (send_rv == -1) {
	    perror("send C1");
	    close(sockfd);
	    exit(0);
	}
	printf("client: sent C1 \'%s\', length of c1 = %lu\n", buffer, strlen(c1));
	// Send C2
	memset(buffer, 0, MAX_MSG_LEN);
	c2 = point_to_hex(group, mul_res[i]->C2);
	memcpy(buffer, c2, MAX_MSG_LEN);
	send_rv = send(sockfd, buffer, sizeof(buffer), 0);
	if (send_rv == -1) {
	    perror("send C2");
	    close(sockfd);
	    exit(0);
	}
	printf("client: sent C2 \'%s\', length of c2 = %lu\n", buffer, strlen(c2));
    }

    close(sockfd);
    BN_CTX_free(ctx);

    return 0;
}
