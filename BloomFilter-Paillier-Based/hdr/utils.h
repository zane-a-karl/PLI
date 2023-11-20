#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>  // inet_ntop()
#include <ctype.h>      // isdigit()
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>     // sigemptyset()
#include <stdarg.h>     // va_start(), va_arg(), va_end()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // memset()
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>     // close()
#include <gmp.h>
#include <paillier.h>
#include <bloom.h>


#define SUCCESS 1
#define FAILURE 0
#define FIXED_LEN 10
#define MAX_MSG_LEN 2048
#define MAX_FILE_BYTES 256

enum PartyType {
    CLIENT,
    SERVER
};

enum MessageType {
    UnsignedLong,
    Integer,
    PaillierPlaintext,
    PaillierCiphertext,
    PaillierPubkey
};

int
general_error (
    char *error_msg);

void
set_security_param (
    int  *dst,
    char *src);

void *
get_in_addr (
    struct sockaddr *sa);

void
sigchld_handler (
    int s);

void
hardcode_socket_parameters (
    struct addrinfo **service_info,
    const char        *port_number,
    enum PartyType            type,
    char                 *hostname);

void
set_socket_and_bind (
    int    *socket_file_descriptor,
    struct addrinfo **service_info);

void
set_socket_and_connect (
    int    *socket_file_descriptor,
    struct addrinfo **service_info);

void
start_server (
    int socket_file_descriptor,
    const int          backlog);

void
reap_all_dead_processes (
    void);

int
accept_connection (
    int listener_sockfd);

int
generate_list_entries (
    uint64_t **entries,
    int    num_entries);

int
parse_file_for_num_entries (
    int *num_entries,
    char   *filename);

int
parse_file_for_list_entries (
    paillier_plaintext_t **entries,
    int                num_entries,
    char                 *filename);

char *
pad_leading_zeros (
    char *msg);

int
serialize_ul (
    char  **serialized,
    unsigned long *msg);

int
serialize_int (
    char **serialized,
    int          *msg);

int
serialize_paillier_ptxt (
    char         **serialized,
    paillier_plaintext_t *msg);

int
serialize_paillier_ctxt (
    char          **serialized,
    paillier_ciphertext_t *msg);

int
serialize_paillier_pk (
    char      **serialized,
    paillier_pubkey_t *msg);

int
send_msg_length (
    int  file_descriptor,
    unsigned long length);

int
send_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    int         print_flag,
    enum MessageType mtype);

int
recv_msg_length (
    int   file_descriptor,
    unsigned long *length);

int
deserialize_ul (
    unsigned long *msg,
    char          *buf);

int
deserialize_int (
    int  *msg,
    char *buf);

int
deserialize_paillier_ptxt (
    paillier_plaintext_t **msg,
    char                  *buf);

int
deserialize_paillier_ctxt (
    paillier_ciphertext_t **msg,
    char                   *buf);

int
deserialize_paillier_pk (
    paillier_pubkey_t **msg,
    char               *buf);

int
recv_msg (
    int       file_descriptor,
    void                 *msg,
    char            *conf_str,
    int            print_flag,
    enum MessageType    mtype);

#endif//_UTILS_H_
