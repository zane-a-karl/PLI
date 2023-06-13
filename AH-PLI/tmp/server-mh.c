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
#include <sys/wait.h>
#include <signal.h>

#include <ecelgamal.h>

#define PORT "3490"      // The port users will be connecting to.
#define PKLEN 128        // public key length: it's actually 66 but gave it some space just in case
#define BACKLOG 10
#define MAX_MSG_LEN 1024 // number of bytes in a message


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

void sigchld_handler (int s)
{
    // waitpid() might overwrite errno so we save and restore it.
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// get sockaddr IPv4 or IPv6
void *get_in_addr (struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
	return &( ((struct sockaddr_in  *)sa)->sin_addr );
    } else {
	return &( ((struct sockaddr_in6  *)sa)->sin6_addr );
    }
}

int main (int argc, char **argv)
{
    int sockfd, new_fd; // listen on sockfd and new connection on new_fd.
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; //connector's addr info
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char *s = (char *)calloc(INET6_ADDRSTRLEN, sizeof(*s));
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // Use my IP.

    if ( (rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0 ) {
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	return 1;
    }

    // Loop through all the results and bind to the first one we can.
    for (p = servinfo; p != NULL; p = p->ai_next) {
	if ( (sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
	    perror("server: socket");
	    continue;
	}

	if ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1 ) {
	    perror("setsockopt");
	    exit(1);
	}

	if ( bind(sockfd, p->ai_addr, p->ai_addrlen) == -1 ) {
	    close(sockfd);
	    perror("server: bind");
	    continue;
	}

	break;
    }

    freeaddrinfo(servinfo); // all done with this struct.

    if (p == NULL) {
	fprintf(stderr, "server: failed to bind\n");
	exit(1);
    }

    if ( listen(sockfd, BACKLOG) == -1) {
	perror("listen");
	exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if ( sigaction(SIGCHLD, &sa, NULL) == -1 ) {
	perror("sigaction");
	exit(1);
    }

    printf("server: waiting for connections...\n");
    while (1) { // main accept() loop
	sin_size = sizeof (their_addr);
	if ( (new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size) ) == -1 ) {
	    //perror("accept");
	    continue;
	}

	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
	printf("server: got connection from %s\n", s);

	if ( !fork() ) { // this is the child process
	    close(sockfd); // child doesn't need the listener

	    // Start the protocol
	    const int num_entries = 3;
	    int numrecv_bytes;
	    gamal_key_t server_key;
	    gamal_ciphertext_t server_cipher[num_entries];
	    gamal_ciphertext_t client_cipher[num_entries];
	    dig_t plain[num_entries];
	    bsgs_table_t table;
	    int tablebits = 16; // got this from testing.cpp bench_elgamal
	    srand (time(NULL));
	    gamal_init(CURVE_256_SEC);
	    EC_GROUP *group = gamal_get_current_group();
	    gamal_generate_keys(server_key);
	    gamal_init_bsgs_table(table, (dig_t) 1L << tablebits);

	    char *server_pk = point_to_hex(group, server_key->Y);

	    // Generate server list entries i.e. {0, 1, 2}
	    for (int i=0; i<num_entries; i++) {
		/* plain[i] = ((dig_t) rand()) * i % (((dig_t)1L) << 32); */
		plain[i] = (dig_t)i;
	    }

	    // send pk2 to client
	    int send_rv = send(new_fd, server_pk, strnlen(server_pk, PKLEN), 0);
	    if (send_rv == -1) {
		perror("send");
		close(new_fd);
		exit(0);
	    }
	    printf("server: sent pk2 %s\n", server_pk);

	    // encrypt server list entries and send them to client
	    char buffer[MAX_MSG_LEN];
	    char *c1, *c2;
	    for (int i=0; i<num_entries; i++) {
		gamal_encrypt(server_cipher[i], server_key, plain[i]);
		// Send C1
		memset(buffer, 0, MAX_MSG_LEN);
		c1 = point_to_hex(group, server_cipher[i]->C1);
		memcpy(buffer, c1, MAX_MSG_LEN);
		send_rv = send(new_fd, buffer, sizeof(buffer), 0);
		if (send_rv == -1) {
		    perror("send C1");
		    close(new_fd);
		    exit(0);
		}
		printf("server: sent C1 \'%s\', length of c1 = %lu\n", buffer, strlen(c1));
		// Send C2
		memset(buffer, 0, MAX_MSG_LEN);
		c2 = point_to_hex(group, server_cipher[i]->C2);
		memcpy(buffer, c2, MAX_MSG_LEN);
		send_rv = send(new_fd, buffer, sizeof(buffer), 0);
		if (send_rv == -1) {
		    perror("send C2");
		    close(new_fd);
		    exit(0);
		}
		printf("server: sent C2 \'%s\', length of c2 = %lu\n", buffer, strlen(c2));
	    }

	    // Recv mul_res entries from client
	    for (int i=0; i<num_entries; i++) {
		// Recv C1
		memset(buffer, 0, MAX_MSG_LEN);
		numrecv_bytes = recv(new_fd, buffer, MAX_MSG_LEN, 0);
		if ( numrecv_bytes  == -1 ) {
		    perror("recv C1");
		    exit(1);
		}
		buffer[numrecv_bytes] = '\0';
		printf("server: received C1  '%s'\n", buffer);
		client_cipher[i]->C1 = hex_to_point(group, buffer);
		// Recv C2
		memset(buffer, 0, MAX_MSG_LEN);
		numrecv_bytes = recv(new_fd, buffer, MAX_MSG_LEN, 0);
		if ( numrecv_bytes  == -1 ) {
		    perror("recv C2");
		    exit(1);
		}
		buffer[numrecv_bytes] = '\0';
		printf("server: received C2  '%s'\n", buffer);
		client_cipher[i]->C2 = hex_to_point(group, buffer);
	    }
	    
	}
	close(new_fd); // parent doesn't need this.
    }

    return 0;
}
