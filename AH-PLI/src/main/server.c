#include "../../hdr/utils.h"
#include "../../hdr/protocols/utils.h"


#define PORT "3490" /* Clients will connect to this port on the server */
#define LISTENER_QUEUE_LEN 10

int
main (
    int    argc,
    char **argv)
{
    int r;
    int sockfd; /* Listen on sockfd */
    int new_fd; /* New connection on new_fd */
    struct addrinfo *service_info; /* Field values for port "service" */
    InputArgs ia;

    r = parse_input_args(&ia, argc, argv);
    if (!r) { return general_error("Failed within parse_input_args"); }
    hardcode_socket_parameters(&service_info, PORT, SERVER, NULL);
    set_socket_and_bind(&sockfd, &service_info);
    freeaddrinfo(service_info);
    start_server(sockfd, LISTENER_QUEUE_LEN);
    reap_all_dead_processes();

    printf("server: ");
    printf("waiting for connections...\n");
    while (1) {  /* accept() loop */
	new_fd = accept_connection(sockfd);
	if (new_fd == -1) { continue; }

	if (!fork()) {
	    /* Child process doesn't need listener socket */
	    close(sockfd);
	    /* Start the protocol */
	    PliProtocol protocol = callback[SERVER][ia.pmeth][ia.eflav][ia.htype];
	    if (!protocol) { return general_error("Failed to find protocol in Lookup Table"); }
	    r = run(protocol, new_fd, ia);
	    if (!r) {
		close(new_fd);
		return general_error("Server: Failed during pli execution");
	    }
	} // fork
	close(new_fd);
    } //while loop
    close(sockfd);
    return 0;
}
