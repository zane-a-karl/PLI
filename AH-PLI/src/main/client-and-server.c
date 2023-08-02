#include "../hdr/protocol-utils.h"


#define LISTENER_QUEUE_LEN 10

int
main (int    argc,
      char **argv)
{
    int r;
    pid_t fork_result;
    pid_t client_proc_id;
    pid_t server_cnntn_proc_id;
    int client_proc_status;
    int server_cnntn_proc_status;
    int accept_flag;
    int sockfd_server; /* Listen on sockfd_server */
    int sockfd_client;
    int new_fd_server; /* New connection on new_fd_server */
    struct addrinfo *service_info_server; /* Field values for port "service" */
    struct addrinfo *service_info_client; /* Field values for port "service" */
    char *hostname;
    enum PliMethod pmeth;
    enum ElgamalFlavor eflav;
    enum HomomorphismType htype;
    int sec_par;
    char *filename_server;
    char *filename_client;
    int port_number;
    char *port;
    /* The port server accepts connections on, and the port client connects to at server. */
    const int PORT = 3490;

    if (argc != 8) {
	printf("usage: %s", argv[0]);
	printf("<hostname> <pli method>");
	printf("<security parameter>");
	printf("<filename_server> <filename_client>\n");
	printf("<EG or ECEG> <MH or AH>\n");
	return 1;
    }
    hostname        =                                  argv[1];
    r               =        str_to_pli_method(&pmeth, argv[2]);
    r               =                str2int(&sec_par, argv[3]);
    filename_server =                                  argv[4];
    filename_client =                                  argv[5];
    r               =    str_to_elgamal_flavor(&eflav, argv[6]);
    r               = str_to_homomorphism_type(&htype, argv[7]);

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
	/* Child process for Client */
	close(sockfd_server);
	hardcode_socket_parameters(&service_info_client, port, CLIENT, hostname);
	set_socket_and_connect(&sockfd_client, &service_info_client);
	freeaddrinfo(service_info_client);
	/* Start the protocol */
	r = run(sockfd, EG, MH, sec_par, filename);
	r = run(pli_callback[CLIENT][pmeth][eflav][htype], sockfd, sec_par, filename_client);
	if (!r) {
	    perror("Client: Failed during pli execution");
	    return 1;
	} else {
	    printf("Client: Completed pli execution\n");
	    return 0;
	}
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
	    /* Child process for server accepted connection */
	    close(sockfd_server);
	    /* Start the protocol */
	    r = run(pli_callback[SERVER][pmeth][eflav][htype], new_fd, sec_par, filename_server);
	    if (!r) {
		perror("Server: Failed during pli execution");
		return 1;
	    } else {
		printf("Server: Completed pli execution\n");
		return 0;
	    }
	    close(new_fd_server);
	} /* fork server connection */
	server_cnntn_proc_id = fork_result;
	close(new_fd_server);
    } /* while loop */
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
