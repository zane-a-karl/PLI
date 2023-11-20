#include "../hdr/pli.h"


#define PORT "3490" // the port client will be connecting to

int
main (
    int    argc,
    char **argv)
{
    int r;
    int sockfd;
    struct addrinfo *service_info;
    char *hostname;
    int sec_par;
    char *filename;

    if (argc != 4) {
	printf("usage: ./<executable> <hostname> <security parameter> <filename>\n");
	exit(1);
    }
    hostname          = argv[1];
    set_security_param(&sec_par, argv[2]);    
    filename          = argv[3];
    hardcode_socket_parameters(&service_info, PORT, CLIENT, hostname);
    set_socket_and_connect(&sockfd, &service_info);
    freeaddrinfo(service_info);

    // Start the protocol
    r = client_run_bf_paillier_pli(sockfd, sec_par, filename);
    if (!r) {
	close(sockfd);
	perror("client: Failed during pli execution");
	exit(1);
    }
    close(sockfd);
    return 0;
}
