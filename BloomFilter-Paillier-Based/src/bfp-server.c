#include "../hdr/pli.h"


#define PORT "3490"      // The port users will be connecting to.
#define LISTENER_QUEUE_LEN 10

int
main (
    int    argc,
    char **argv)
{
    int r;
    /* pid_t fork_result; */
    /* pid_t server_cnntn_proc_id;     */
    int sockfd; // listen on sockfd
    int new_fd; // new connection on new_fd.
    struct addrinfo *service_info; // field values for port "service"
    int sec_par;
    char *filename;

    if (argc != 3) {
	printf("usage: ./<executable> <security parameter> <filename>\n");
	exit(1);
    }
    set_security_param(&sec_par, argv[1]);
    filename          = argv[2];
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
	/* fork_result = fork(); */
	/* if (fork_result == -1) { */
	/*     perror("Failed to execute fork() for client process"); */
	/*     return 1; */
	/* } else if (fork_result == 0) {	 */
	    // Child process doesn't need the listener
	    /* close(sockfd); */
	    // Start the protocol
	    r = server_run_bf_paillier_pli(new_fd, sec_par, filename);
	    if (!r) {
		perror("Server: Failed pli execution");
	    } else {
		printf("Server: Completed pli execution\n");
	    }
	    close(new_fd);
	    break;
	    /* return 0;	     */
	/* } // fork */
	/* server_cnntn_proc_id = fork_result; */
	/* printf("server_cnntn_proc_id = %d\n", server_cnntn_proc_id); */
	/* close(new_fd); */
    } //while loop
    close(sockfd);
    return 0;
}
