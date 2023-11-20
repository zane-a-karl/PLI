#include "../hdr/pli.h"


#define LISTENER_QUEUE_LEN 10
extern int SEC_PAR;

int
main (
    int    argc,
    char **argv)
{
    int r;
    pid_t fork_result;
    pid_t client_proc_id;
    pid_t server_cnntn_proc_id;
    int client_proc_status;
    int server_cnntn_proc_status;
    int accept_flag;
    int sockfd_server;
    int sockfd_client;
    int new_fd_server;
    struct addrinfo *service_info_server; // field values for port "service"
    struct addrinfo *service_info_client; // field values for port "service"
    char *hostname;
    int sec_par;
    char *filename_server;
    char *filename_client;
    int port_number;
    char *port;
    /* The port server accepts connections on, and the port client connects to at server. */
    const int PORT = 3490;

    if (argc != 5) {
	printf("usage: ./<executable> <hostname> <security parameter> <filename_server> <filename_client>\n");
	exit(1);
    }
    hostname          = argv[1];
    set_security_param(&sec_par, argv[2]);
    filename_server   = argv[3];
    filename_client   = argv[4];

    srand (time(NULL));
    port_number = PORT + (rand() % PORT);
    port = calloc(16, sizeof(char));
    snprintf(port, 16, "%d", port_number);
    hardcode_socket_parameters(&service_info_server, port, SERVER, NULL);
    set_socket_and_bind(&sockfd_server, &service_info_server);
    freeaddrinfo(service_info_server);
    start_server(sockfd_server, LISTENER_QUEUE_LEN);
    reap_all_dead_processes();

    fork_result = fork();
    if (fork_result == -1) {
	perror("Failed to execute fork() for client process");
	return 1;
    } else if (fork_result == 0) {
	// Child process for Client
	close(sockfd_server);
	hardcode_socket_parameters(&service_info_client, port, CLIENT, hostname);
	set_socket_and_connect(&sockfd_client, &service_info_client);
	freeaddrinfo(service_info_client);
	// Start the protocol
	r = client_run_bf_paillier_pli(sockfd_client, sec_par, filename_client);
	if (!r) {
	    perror("client: Failed during pli execution");
	    return 1;
	}
	printf("client: Completed pli execution\n");
	close(sockfd_client);
	return 0;
    }
    client_proc_id = fork_result;

    printf("server: ");
    printf("waiting for connections...\n");
    accept_flag = 0;
    while (!accept_flag) {
	new_fd_server = accept_connection(sockfd_server);
	if (new_fd_server == -1) {
	    continue;
	}
	accept_flag = 1;
	fork_result = fork();
	if ( fork_result == -1 ) {
	    perror("Failed to execute fork() for server connection");
	    return 1;
	} else if (fork_result == 0) {
	    // Child process for server accepted connection
	    close(sockfd_server);
	    // Start the protocol
	    r = server_run_bf_paillier_pli(new_fd_server, sec_par, filename_server);
	    if (!r) {
		perror("server: Failed during pli execution");
		return 1;
	    } else {
		fprintf(stderr, "server: Completed pli execution\n");
		return 0;
	    }
	    close(new_fd_server);
	} // fork server connection
	server_cnntn_proc_id = fork_result;
	close(new_fd_server);
    } // while loop
    reap_all_dead_processes();
    fork_result = waitpid(client_proc_id, &client_proc_status, WUNTRACED);
    if (fork_result != -1) {
	printf("join on client_proc_id(%d) = %d\n", client_proc_id, fork_result);
	perror("Failed to join client_proc");
    }
    fork_result = waitpid(server_cnntn_proc_id, &server_cnntn_proc_status, WUNTRACED);
    if (fork_result != -1) {
	printf("join on server_cnntn_proc_id(%d) = %d\n", server_cnntn_proc_id, fork_result);
	perror("Failed to join server_cnntn_proc");
    }
    if (WIFSIGNALED(client_proc_status)) {
	int client_proc_sig_status = WTERMSIG(client_proc_status);
	printf("client proc exited with sig status: %d\n", client_proc_sig_status);
    }
    if (WIFEXITED(server_cnntn_proc_status)) {
	int server_cnntn_proc_exit_status = WEXITSTATUS(server_cnntn_proc_status);
	printf("server cnntn proc exited with status: %d\n", server_cnntn_proc_exit_status);
    }
    close(sockfd_server);
    return 0;
}
