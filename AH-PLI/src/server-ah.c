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

#include <openssl/bn.h>

#include "../hdr/utils.h"
#include "../hdr/elgamal-utils.h"
#include "../hdr/ah-elgamal.h"


#define PORT "3490"      // The port users will be connecting to.
#define PKLEN 128        // public key length: it's actually 66 but gave it some space just in case
#define BACKLOG 10
#define MAX_MSG_LEN 1024 // number of bytes in a message

int main (int argc, char **argv)
{
    int sockfd; // listen on sockfd
    int new_fd; // new connection on new_fd.
    struct addrinfo hints; // field values for the listener socket
    struct addrinfo *servinfo; // field values for port "service"
    struct addrinfo *p;    // Iterator through the port services
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

	inet_ntop(their_addr.ss_family,
		  get_in_addr((struct sockaddr *)&their_addr),
		  s, sizeof s);
	printf("server: got connection from %s\n", s);

	if ( !fork() ) { // this is the child process
	    close(sockfd); // child doesn't need the listener

	    // Start the protocol
	    int r;
	    const int num_entries = 3;
	    unsigned char buffer[MAX_MSG_LEN];
	    GamalKeys server_keys;
	    GamalCiphertext server_cipher[num_entries];
	    GamalCiphertext client_cipher[num_entries];
	    uint64_t plain[num_entries];

	    // Generate Keys
	    r = generate_elgamal_keys(&server_keys);
	    if (!r) {
		perror("Failed to gen EG keys");
		exit(1);
	    }

	    // Generate server list entries
	    // i.e. {0, 1, 2}
	    /* srand (time(NULL)); */
	    for (int i=0; i<num_entries; i++) {
		/* plain[i]  = ((uint64_t) rand()) * i; */
		/* plain[i] %= ((1ULL) << 32); */
		plain[i] = (uint64_t)i;
	    }
	    printf("generated server list\n");

	    // send pk2 to client
	    memset(buffer, 0, MAX_MSG_LEN);
	    r = BN_bn2bin(server_keys.pk->mul_mask,
			  buffer);
	    if (!r) {
		close(new_fd);
		perror("Error pk2 bn2bin");
		exit(1);
	    }
	    r = send(new_fd, buffer,
		     strnlen(buffer, MAX_MSG_LEN),
		     0);
	    if (r == -1) {
		perror("Failed to send serverpk");
		close(new_fd);
		exit(0);
	    }
	    printf("server: sent pk2 =");
	    printf(" %s\n",
		   BN_bn2hex(server_keys.pk->modulus));

	    // encrypt server list entries and send them to client
	    for (int i=0; i < num_entries; i++) {
		ah_elgamal_encrypt(&server_cipher[i],
				   server_keys.pk,
				   &plain[i]);
		// Send C1
		memset(buffer, 0, MAX_MSG_LEN);
		r = BN_bn2bin(server_cipher[i].c1,
			      buffer);
		if (!r) {
		    perror("Error c1 bn2bin");
		    close(new_fd);
		    exit(1);
		}
		r = send(new_fd, buffer,
			 strnlen(buffer,
				 MAX_MSG_LEN), 0);
		if (r == -1) {
		    perror("send C1");
		    close(new_fd);
		    exit(0);
		}
		printf("server: sent C1 \'%s\',",
		       buffer);
		printf("length of c1 = %d\n", r);
		// Send C2
		memset(buffer, 0, MAX_MSG_LEN);
		r = BN_bn2bin(server_cipher[i].c2,
			      buffer);
		if (!r) {
		    perror("Error c2 bn2bin");
		    close(new_fd);
		    exit(1);
		}
		r = send(new_fd, buffer,
			 strnlen(buffer,
				 MAX_MSG_LEN), 0);
		if (r == -1) {
		    perror("failed to send C2");
		    close(new_fd);
		    exit(0);
		}
		printf("server: sent C2 \'%s\',",
		       buffer);
		printf("length of c2 = %d\n", r);
	    }

	    // Recv mul_res entries from client
	    for (int i=0; i<num_entries; i++) {
		// Recv C1
		memset(buffer, 0, MAX_MSG_LEN);
		r = recv(new_fd, buffer,
			 MAX_MSG_LEN, 0);
		if ( r  == -1 ) {
		    perror("failed to recv C1");
		    exit(1);
		}
		buffer[r] = '\0';
		printf("server: recvd c1 '%s'\n",
		       buffer);
		client_cipher[i].c1 =
		    BN_bin2bn(buffer, r, NULL);
		// Recv C2
		memset(buffer, 0, MAX_MSG_LEN);
		r = recv(new_fd, buffer,
			 MAX_MSG_LEN, 0);
		if ( r  == -1 ) {
		    perror("recv C2");
		    exit(1);
		}
		buffer[r] = '\0';
		printf("server: recvd c2 '%s'\n",
		       buffer);
		client_cipher[i].c2 =
		    BN_bin2bn(buffer, r, NULL);
	    }

	}
	// parent doesn't need this.
	close(new_fd);
    }

    return 0;
}
