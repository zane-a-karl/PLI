#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>  // inet_ntop()
#include <ctype.h>      // isdigit()
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <signal.h>     // sigemptyset()
#include <stdarg.h>     // va_start(), va_arg(), va_end()
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
#define MAX_MSG_LEN 2048
#define MAX_FILE_BYTES 256

enum PartyType {
    CLIENT,
    SERVER,
    NUM_PARTY_TYPES
};

enum MessageType {
    Bignum,
    Ecpoint,
    Integer,
    NUM_MESSAGE_TYPES
};

int
general_error (char *error_msg);

int
openssl_error (char *error_msg);

int
log_base2 (int sec_par);

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
parse_file_for_list_entries (BIGNUM      **entries,
			     int       num_entries,
			     char        *filename);

char *
pad_leading_zeros (char *msg);

int
serialize_int (char **serialized,
	       int          *msg);

int
serialize_ecpoint (char   **serialized,
		   EC_POINT       *msg,
		   EC_GROUP     *group);

int
serialize_bignum (char   **serialized,
		  BIGNUM         *msg);

int
send_msg_length (int  file_descriptor,
		 unsigned long length);

int
send_msg (int    file_descriptor,
	  void              *msg,
	  char         *conf_str,
	  enum MessageType mtype,
	  ...);

int
recv_msg_length (int   file_descriptor,
		 unsigned long *length);

int
deserialize_bignum (BIGNUM **msg,
		    char    *buf);

int
deserialize_int (int  *msg,
		 char *buf);

int
deserialize_ecpoint (EC_POINT  **msg,
		     char       *buf,
		     EC_GROUP *group);

int
recv_msg (int       file_descriptor,
	  void                 *msg,
	  char            *conf_str,
	  enum MessageType    mtype,
	  ...);

#endif//_UTILS_H_
