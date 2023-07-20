#include "../hdr/elgamal-pli.h"


#define PORT "3490"      // The port users will be connecting to.
#define LISTENER_QUEUE_LEN 10
extern int SEC_PAR;

int
main (int argc,
      char **argv)
{
    int r;
    int sockfd; // listen on sockfd
    int new_fd; // new connection on new_fd.
    struct addrinfo *service_info; // field values for port "service"
    char *homomorphism_type;
    char *filename;

    if (argc != 4) {
	// MH = multiplicatively homomorphic
	// AH = additively homomorphic
	printf("usage: ./<executable> <MH or AH> <security parameter> <filename>\n");
	exit(1);
    }
    homomorphism_type = argv[1];
    set_security_param(&SEC_PAR, argv[2]);
    filename          = argv[3];
    hardcode_socket_parameters(&service_info, PORT, SERVER, NULL);
    set_socket_and_bind(&sockfd, &service_info);
    freeaddrinfo(service_info);
    // Might be able to fix some of the double send problems by setting this to 1
    start_server(sockfd, LISTENER_QUEUE_LEN);
    reap_all_dead_processes();

    printf("server: ");
    printf("waiting for connections...\n");
    while (1) { // main accept() loop
	new_fd = accept_connection(sockfd);
	if (new_fd == -1) {
	    continue;
	}

	if ( !fork()) {
	    // Child process doesn't need the listener
	    close(sockfd);
	    // Start the protocol
	    r = strncmp(homomorphism_type, "AH", 3);
	    if (r == 0) {
		r = server_run_elgamal_pli(new_fd, AH, filename);
	    } else {
		r = server_run_elgamal_pli(new_fd, MH, filename);
	    }
	    if (!r) {
		close(new_fd);
		perror("server: Failed during pli execution");
		exit(1);
	    }
	}
	// Parent process doesn't need client fd
	close(new_fd);
    }

    return 0;
}
