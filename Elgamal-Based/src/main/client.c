#include <stdlib.h>
#include <openssl/bn.h>
#include <netdb.h>
#include <openssl/ec.h>
#include "../../hdr/input-args/utils.h" /* InputArgs, parse_input_args() */
#include "../../hdr/network/utils.h"    /* hardcode_socket_parameters(), set_socket_and_connect() */
#include "../../hdr/error/utils.h"      /* general_error() */
#include "../../hdr/protocols/utils.h"  /* PliProtocol, run() */
#include <unistd.h>		        /* close() */


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
