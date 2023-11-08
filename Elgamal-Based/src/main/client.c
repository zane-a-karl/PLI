#include "../../hdr/utils.h"
#include "../../hdr/protocols/utils.h"


/* Client connects to this port at the server */
#define PORT "3490"

int
main (
    int    argc,
    char **argv)
{
    int r;
    int sockfd;
    struct addrinfo *service_info;
    InputArgs ia;

    r = parse_input_args(&ia, argc, argv, CLIENT);
    if (!r) { return general_error("Failed within parse_input_args"); }
    hardcode_socket_parameters(&service_info, PORT, CLIENT, ia.hostname);
    set_socket_and_connect(&sockfd, &service_info);
    freeaddrinfo(service_info);

    /* Start the protocol */
    PliProtocol protocol = callback[CLIENT][ia.pmeth][ia.eflav][ia.htype];
    if (!protocol) { return general_error("Failed to find protocol in Lookup Table"); }
    r = run(protocol, sockfd, ia);
    if (!r) {
	close(sockfd);
	return general_error("Client: Failed during pli execution");
    }
    close(sockfd);
    return 0;
}
