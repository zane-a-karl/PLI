#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>  // inet_ntop()
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>     // sigemptyset()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // memset()
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>     // close()

enum PartyType {
    CLIENT, SERVER
};

void *
get_in_addr (struct sockaddr *sa);

void
sigchld_handler (int s);

void
hardcode_socket_parameters (struct addrinfo **service_info,
			    const char        *port_number,
			    enum PartyType            type,
			    char                 *hostname);

void
set_socket_and_bind (int    *socket_file_descriptor,
		     struct addrinfo **service_info);

void
set_socket_and_connect (int    *socket_file_descriptor,
			struct addrinfo **service_info);

void
start_server (int socket_file_descriptor,
	      const int          backlog);

void
reap_all_dead_processes (void);

int
accept_connection (int listener_sockfd);

#endif//_UTILS_H_
