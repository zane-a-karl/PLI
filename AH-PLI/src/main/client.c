#include "../../hdr/protocol-utils.h"

/* Client connects to this port at the server */
#define PORT "3490"

int
main (int    argc,
      char **argv)
{
    int r;
    int sockfd;
    struct addrinfo *service_info;
    char *hostname;
    enum PliMethod pmeth;
    enum ElgamalFlavor eflav;
    enum HomomorphismType htype;
    int sec_par;
    char *filename;

    if (argc != 7) {
	printf("usage: %s", argv[0]);
	printf("<hostname> <pli method>");
	printf("<security parameter> <filename>");
	printf("<EG or ECEG> <MH or AH>\n");
	return 1;
    }
    hostname =                                  argv[1];
    r        =        str_to_pli_method(&pmeth, argv[2]);
    r        =                str2int(&sec_par, argv[3]);
    filename =                                  argv[4];
    r        =    str_to_elgamal_flavor(&eflav, argv[5]);
    r        = str_to_homomorphism_type(&htype, argv[6]);

    hardcode_socket_parameters(&service_info, PORT, CLIENT, hostname);
    set_socket_and_connect(&sockfd, &service_info);
    freeaddrinfo(service_info);

    /* Start the protocol */
    r = run(pli_callback[CLIENT][pmeth][eflav][htype], sockfd, sec_par, filename);
    if (!r) {
	close(sockfd);
	perror("client: Failed during pli execution");
	return 1;
    }
    close(sockfd);
    return 0;
}
