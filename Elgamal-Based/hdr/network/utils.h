#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

/*******************Include Prerequisites******************
#include <netdb.h>                      // struct sockaddr
#include <openssl/bn.h>		        // BIGNUM
#include "../../hdr/input-args/utils.h" // enum PartyType
#include <openssl/ec.h>		        // EC_POINT
#include "../../hdr/macros.h"           // FIXED_LEN
**********************************************************/

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

char *
pad_leading_zeros (
    char *msg);

int
serialize_bignum (
    char **serialized,
    BIGNUM       *msg);

int
serialize_ecpoint (
    char **serialized,
    EC_POINT     *msg,
    EC_GROUP   *group);

int
serialize_int (
    char **serialized,
    int          *msg);

int
serialize_size_t (
    char **serialized,
    size_t       *msg);

int
serialize_uchar (
    char  **serialized,
    unsigned char *msg,
    size_t         len);

int
send_msg_length (
    int  file_descriptor,
    unsigned long length);

int
send_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    enum MessageType mtype,
    ...);

int
recv_msg_length (
    int   file_descriptor,
    unsigned long *length);

int
deserialize_int (
    int  *msg,
    char *buf);

int
deserialize_size_t (
    size_t *msg,
    char   *buf);

int
deserialize_uchar (
    unsigned char **msg,
    char           *buf,
    size_t          len);

int
deserialize_bignum (
    BIGNUM **msg,
    char    *buf);

int
deserialize_ecpoint (
    EC_POINT  **msg,
    char       *buf,
    EC_GROUP *group);

int
recv_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    enum MessageType mtype,
    ...);

#endif//NETWORK_UTILS_H
