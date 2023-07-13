#include "../hdr/elgamal-pli.h"


#define PORT_SERVER "3490"      // The port users will be connecting to.
#define PORT_CLIENT "3490"      // The port users will be connecting to.
#define LISTENER_QUEUE_LEN 10

int
main (int argc,
      char **argv)
{
    int r;
    int sockfd_server;
    int sockfd_client;
    int new_fd_server;
    struct addrinfo *service_info_server; // field values for port "service"
    struct addrinfo *service_info_client; // field values for port "service"    
    char *hostname;    
    char *homomorphism_type;
    char *filename_server;
    char *filename_client;    

    if (argc != 5) {
	// MH = multiplicatively homomorphic
	// AH = additively homomorphic
	fprintf(stderr,
		"usage: ./<executable> <hostname> <MH or AH> <filename_server> <filename_client>\n");
	exit(1);
    }
    hostname = argv[1];
    homomorphism_type = argv[2];
    filename_server = argv[3];
    filename_client = argv[4];    
    hardcode_socket_parameters(&service_info_server, PORT_SERVER, SERVER, NULL);
    set_socket_and_bind(&sockfd_server, &service_info_server);
    freeaddrinfo(service_info_server);
    // Might be able to fix some of the double send problems by setting this to 1
    start_server(sockfd_server, LISTENER_QUEUE_LEN);
    reap_all_dead_processes();
    if(!fork()) {
	hardcode_socket_parameters(&service_info_client, PORT_CLIENT, CLIENT, hostname);
	set_socket_and_connect(&sockfd_client, &service_info_client);
	freeaddrinfo(service_info_client);
	// Start the protocol
	r = strncmp(homomorphism_type, "AH", 3);
	if (r == 0) {
	    r = client_run_elgamal_pli(sockfd_client, AH, filename_client);
	} else {
	    r = client_run_elgamal_pli(sockfd_client, MH, filename_client);
	}
	if (!r) {
	    close(sockfd_client);
	    perror("client: Failed during pli execution");
	    exit(1);
	}	
    }

    printf("server: ");
    printf("waiting for connections...\n");
    while (1) { // main accept() loop
	new_fd_server = accept_connection(sockfd_server);
	if (new_fd_server == -1) {
	    continue;
	}

	if ( !fork()) {
	    // Child process doesn't need the listener
	    close(sockfd_server);
	    // Start the protocol
	    r = strncmp(homomorphism_type, "AH", 3);
	    if (r == 0) {
		r = server_run_elgamal_pli(new_fd_server, AH, filename_server);
	    } else {
		r = server_run_elgamal_pli(new_fd_server, MH, filename_server);
	    }
	    if (!r) {
		close(new_fd_server);
		perror("server: Failed during pli execution");
		exit(1);
	    }
	}
	// Parent process doesn't need client fd
	close(new_fd_server);
    }

    return 0;
}
