#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>  // inet_ntop()
#include <ctype.h>      // isdigit()
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <signal.h>     // sigemptyset()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // memset()
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>     // close()


#define SUCCESS 1
#define FAILURE 0
#define FIXED_LEN 10
#define MAX_MSG_LEN 256
#define MAX_FILE_BYTES 256

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

int
generate_list_entries (uint64_t    **entries,
		       int       num_entries);

int
parse_file_for_num_entries (int        *num_entries,
			    char         *filename);

int
parse_file_for_list_entries (uint64_t    **entries,
			     int       num_entries,
			     char        *filename);

char *
pad_leading_zeros (char *msg);

int
send_bn_msg_length (int file_descriptor,
		    unsigned long length);

int
send_bn_msg (int file_descriptor,
	     BIGNUM     *message,
	     char      *conf_str);

int
recv_bn_msg (int file_descriptor,
	     BIGNUM     *message,
	     char      *conf_str);

#endif//_UTILS_H_
