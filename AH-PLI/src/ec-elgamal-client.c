#include "../hdr/ec-elgamal-pli.h"


#define PORT "3490" // the port client will be connecting to

int
main (int   argc,
      char *argv[])
{
    int r;
    int sockfd;
    struct addrinfo *service_info;
    char *hostname;
    char *homomorphism_type;
    char *filename;

    if (argc != 4) {
	// MH = multiplicatively homomorphic
	// AH = additively homomorphic
	fprintf(stderr, "usage: ./<executable> <hostname> <MH or AH> <filename>\n");
	exit(1);
    }
    hostname = argv[1];
    homomorphism_type = argv[2];
    filename = argv[3];
    hardcode_socket_parameters(&service_info, PORT, CLIENT, hostname);
    set_socket_and_connect(&sockfd, &service_info);
    freeaddrinfo(service_info);

    // Start the protocol
    r = strncmp(homomorphism_type, "AH", 3);
    if (r == 0) {
	r = client_run_ec_elgamal_pli(sockfd, AH, filename);
    } else {
	r = client_run_ec_elgamal_pli(sockfd, MH, filename);
    }
    if (!r) {
	close(sockfd);
	perror("client: Failed during pli execution");
	exit(1);
    }

    return 0;
}
