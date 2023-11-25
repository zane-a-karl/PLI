#include <stdlib.h>
#include <openssl/bn.h>
#include <netdb.h>
#include <openssl/ec.h>
#include "../../hdr/input-args/utils.h"
#include "../../hdr/error/utils.h" /* general_error() */
#include "../../hdr/network/utils.h" /* hardcode_socket_parameters(), set_socket_and_bind/connect(), start_server(), reap_all_dead_processes(), accept_connection() */
#include "../../hdr/protocols/utils.h" /* PliProtocol, run() */
#include <sys/types.h>		/* pid_t, freeaddrinfo() */
#include <sys/wait.h>		/* waitpid() */
#include <stdio.h>		/* snprintf(), perror(), printf() */
#include <unistd.h>		/* fork(), close() */


#define LISTENER_QUEUE_LEN 10

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
    int sockfd_server; /* Listen on sockfd_server */
    int sockfd_client;
    int new_fd_server; /* New connection on new_fd_server */
    struct addrinfo *service_info_server; /* Field values for port "service" */
    struct addrinfo *service_info_client; /* Field values for port "service" */
    InputArgs ia;
    int port_number;
    char *port;
    /* The port server accepts connections on, and the port client connects to at server. */
    const int PORT = 3490;

    r = parse_input_args(&ia, argc, argv, SERVER);
    if (!r) { return general_error("Failed within parse_input_args"); }    
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
	hardcode_socket_parameters(&service_info_client, port, CLIENT, ia.hostname);
	set_socket_and_connect(&sockfd_client, &service_info_client);
	freeaddrinfo(service_info_client);
	/* Start the protocol */
	PliProtocol client_protocol = callback[CLIENT][ia.pmeth][ia.eflav][ia.htype];
	if (!client_protocol) { return general_error("Failed to find protocol in LUT"); }
	r = run(client_protocol, sockfd_client, ia);
	if (!r) {
	    return general_error("Client: Failed during pli execution");
	}
	printf("Client: Completed pli execution\n");
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
	    /* Child process for server accepted connection */
	    close(sockfd_server);
	    /* Start the protocol */
	    PliProtocol server_protocol = callback[SERVER][ia.pmeth][ia.eflav][ia.htype];
	    if (!server_protocol) { return general_error("Failed to find protocol in LUT"); }
	    r = run(server_protocol, new_fd_server, ia);
	    if (!r) {
		return general_error("Server: Failed during pli execution");
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
