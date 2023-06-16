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
	    char *buffer;
	    char *hex;
	    GamalKeys server_keys;
	    GamalCiphertext server_cipher[num_entries];
	    GamalCiphertext client_cipher[num_entries];
	    uint64_t plain[num_entries];
	    uint64_t recovered_plain[num_entries];

	    buffer =
		calloc(MAX_MSG_LEN, sizeof(char));

	    // Generate Keys
	    r = generate_elgamal_keys(&server_keys);
	    if (!r) {
		perror("Failed to gen EG keys");
		exit(1);
	    }

	    // Generate server list entries
	    // i.e. {1, 2, 4}
	    /* srand (time(NULL)); */
	    for (int i=0; i<num_entries-1; i++) {
		/* plain[i]  = ((uint64_t) rand()) * i; */
		/* plain[i] %= ((1ULL) << 32); */
		plain[i] = (uint64_t)i + 1ULL;
		printf("plain[%i] = %" PRIu64 "\n",
		       i, plain[i]);
	    }
	    plain[2] = (uint64_t)4;
	    printf("plain[%i] = %" PRIu64 "\n",
		   2, plain[2]);
	    printf("generated server list\n");

	    // send pk2 to client
	    // 1st: the modulus
	    memset(buffer, 0, MAX_MSG_LEN);
	    hex = BN_bn2hex(server_keys.pk->modulus);
	    if (!hex) {
		close(new_fd);
		perror("Error bn2hex pk2 modulus");
		exit(1);
	    }
	    r = strlcpy(buffer, hex,
			strnlen(hex, MAX_MSG_LEN));
	    if (!r) {
		close(new_fd);
		perror("Error strlcpy hex2buffer");
		exit(1);
	    }
	    free(hex);
	    sleep(1);
	    r = send(new_fd, buffer,
		     strnlen(buffer, MAX_MSG_LEN),
		     0);
	    if (r == -1) {
		perror("Failed to send modulus");
		close(new_fd);
		exit(0);
	    }
	    printf("server: sent pk2 modulus   =");
	    printf(" %s\n", buffer);
	    // 2nd: the generator
	    memset(buffer, 0, MAX_MSG_LEN);
	    hex = BN_bn2hex(server_keys.pk->generator);
	    if (!hex) {
		close(new_fd);
		perror("Error bn2hex pk2 gen");
		exit(1);
	    }
	    r = strlcpy(buffer, hex,
			strnlen(hex, MAX_MSG_LEN));
	    if (!r) {
		close(new_fd);
		perror("Error strlcpy hex2buffer");
		exit(1);
	    }
	    free(hex);
	    sleep(1);
	    r = send(new_fd, buffer,
		     strnlen(buffer, MAX_MSG_LEN),
		     0);
	    if (r == -1) {
		perror("Failed to send generator");
		close(new_fd);
		exit(0);
	    }
	    printf("server: sent pk2 generator =");
	    printf(" %s\n", buffer);
	    // 3rd: the mul_mask
	    memset(buffer, 0, MAX_MSG_LEN);
	    hex = BN_bn2hex(server_keys.pk->mul_mask);
	    if (!hex) {
		close(new_fd);
		perror("Error bn2hex pk2 mask");
		exit(1);
	    }
	    r = strlcpy(buffer, hex,
			strnlen(hex, MAX_MSG_LEN));
	    if (!r) {
		close(new_fd);
		perror("Error strlcpy hex2buffer");
		exit(1);
	    }
	    free(hex);
	    sleep(1);
	    r = send(new_fd, buffer,
		     strnlen(buffer, MAX_MSG_LEN),
		     0);
	    if (r == -1) {
		perror("Failed to send mul_mask");
		close(new_fd);
		exit(0);
	    }
	    printf("server: sent pk2 mul_mask  =");
	    printf(" %s\n", buffer);

	    // encrypt server list entries and send them to client
	    for (int i=0; i < num_entries; i++) {
		ah_elgamal_encrypt(&server_cipher[i],
				   server_keys.pk,
				   &plain[i]);
		// Send C1
		memset(buffer, 0, MAX_MSG_LEN);
		hex = BN_bn2hex(server_cipher[i].c1);
		if (!hex) {
		    close(new_fd);
		    perror("Error bn2hex c1");
		    exit(1);
		}
		r = strlcpy(buffer, hex,
			    strnlen(hex, MAX_MSG_LEN));
		if (!r) {
		    close(new_fd);
		    perror("Error strlcpy hex2buffer");
		    exit(1);
		}
		free(hex);
		sleep(1);
		r = send(new_fd, buffer,
			 strnlen(buffer,
				 MAX_MSG_LEN), 0);
		if (r == -1) {
		    perror("send C1");
		    close(new_fd);
		    exit(0);
		}
		printf("server: sent c1 \'%s\'\n",
		       buffer);
		// Send C2
		memset(buffer, 0, MAX_MSG_LEN);
		hex = BN_bn2hex(server_cipher[i].c2);
		if (!hex) {
		    close(new_fd);
		    perror("Error bn2hex c2");
		    exit(1);
		}
		r = strlcpy(buffer, hex,
			    strnlen(hex, MAX_MSG_LEN));
		if (!r) {
		    close(new_fd);
		    perror("Error strlcpy hex2buffer");
		    exit(1);
		}
		free(hex);
		sleep(1);
		r = send(new_fd, buffer,
			 strnlen(buffer,
				 MAX_MSG_LEN), 0);
		if (r == -1) {
		    perror("failed to send C2");
		    close(new_fd);
		    exit(0);
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
		    exit(1);
		}
		buffer[r] = '\0';
		printf("server: recv c1 '%s'\n",
		       buffer);
		client_cipher[i].c1 = BN_new();
		r = BN_hex2bn(&client_cipher[i].c1,
			      buffer);
		// Recv C2
		memset(buffer, 0, MAX_MSG_LEN);
		r = recv(new_fd, buffer,
			 MAX_MSG_LEN, 0);
		if ( r  == -1 ) {
		    perror("recv C2");
		    exit(1);
		}
		buffer[r] = '\0';
		printf("server: recv c2 '%s'\n",
		       buffer);
		client_cipher[i].c2 = BN_new();
		r = BN_hex2bn(&client_cipher[i].c2,
			      buffer);
	    }

	    // Decrypt the client ciphertext
	    for (int i=0; i<num_entries; i++) {
		r = ah_elgamal_decrypt(&recovered_plain[i],
				       &server_keys,
				       &client_cipher[i]);
		if(!r) {
		    perror("Failed recvr plain");
		    exit(1);
		}
	    }
	    printf("Successfully decrypted\n");
	    for (int i=0; i<num_entries; i++) {
		printf("recovered_plain[%i] = %" PRIu64 "\n", i, recovered_plain[i]);
		if (recovered_plain[i]==0) {
		    printf("Found a match!\n");
		}
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
	    }
	    free(buffer);
	}
	// parent doesn't need this.
	close(new_fd);
    }

    return 0;
}
