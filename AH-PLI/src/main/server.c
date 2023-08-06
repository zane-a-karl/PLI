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
    enum PliMethod pmeth;
    enum ElgamalFlavor eflav;
    enum HomomorphismType htype;
    int sec_par;
    char *filename;

    if (argc != 6) {
	printf("usage: %s", argv[0]);
	printf("<pli method>");
	printf("<security parameter> <filename>");
	printf("<EG or ECEG> <MH or AH>\n");
	return 1;
    }
    r        =        str_to_pli_method(&pmeth, argv[1]);
    r        =             str_to_int(&sec_par, argv[2]);
    filename =                                  argv[3];
    r        =    str_to_elgamal_flavor(&eflav, argv[4]);
    r        = str_to_homomorphism_type(&htype, argv[5]);

    hardcode_socket_parameters(&service_info, PORT, SERVER, NULL);
    set_socket_and_bind(&sockfd, &service_info);
    freeaddrinfo(service_info);
    // Might be able to fix some of the double send problems by setting this to 1
    start_server(sockfd, LISTENER_QUEUE_LEN);
    reap_all_dead_processes();

    printf("server: ");
    printf("waiting for connections...\n");
    while (1) {  /* main accept() loop */
	new_fd = accept_connection(sockfd);
	if (new_fd == -1) { continue; }

	if ( !fork()) {
	    /* Child process doesn't need listener socket */
	    close(sockfd);
	    /* Start the protocol */
	    r = run(callback[SERVER][pmeth][eflav][htype], new_fd, sec_par, filename);
	    if (!r) {
		close(new_fd);
		perror("Server: Failed during pli execution");
		return 1;
	    }
	} // fork
	close(new_fd);
    } //while loop
    close(sockfd);
    return 0;
}
