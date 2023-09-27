#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>  // inet_ntop()
#include <ctype.h>      // isdigit()
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>     // sigemptyset()
#include <stdarg.h>     // va_start(), va_arg(), va_end()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     // memset()
#include <sys/wait.h>   // wait()
#include <sys/types.h>
#include <sys/socket.h> // send(), recv()
#include <unistd.h>     // close(), sleep(), fork()


#define SUCCESS 1
#define FAILURE 0
#define FIXED_LEN 10
#define MAX_MSG_LEN 2048
#define MAX_FILE_BYTES 8192

enum PartyType {
    CLIENT,
    SERVER,
    NUM_PARTY_TYPES
};

enum MessageType {
    Integer,
    SizeT,
    UnsignedChar,
    Bignum,
    Ecpoint,
    NUM_MESSAGE_TYPES
};

enum PliMethod {
    PLI,			/* 0 */
    PLI_ca,			/* 1 */
    t_PLI,			/* 2 */
    PLI_x,			/* 3 */
    t_PLI_ca,			/* 4 */
    t_PLI_x,			/* 5 */
    NUM_PLI_METHODS
};

/* EG = regular Elgamal,
   ECEG = Elliptic Curve Elgamal */
enum ElgamalFlavor {
    EG,				/* 0 */
    ECEG,			/* 1 */
    NUM_ELGAMAL_FLAVORS
};

/* AH = additively homomorphic,
   MH = multiplicatively homomorphic */
enum HomomorphismType {
    AH,				/* 0 */
    MH,				/* 1 */
    NUM_HOMOMORPHISM_TYPES
};

typedef struct InputArgs {
    char              *hostname;
    enum PliMethod        pmeth;
    enum ElgamalFlavor    eflav;
    enum HomomorphismType htype;
    size_t               secpar;
    size_t            threshold;
    char       *client_filename;
    char       *server_filename;
} InputArgs;

int
parse_input_args (
    InputArgs *ia,
    int      argc,
    char   **argv);

int
str_to_pli_method (
    enum PliMethod *pm,
    char          *str);

int
str_to_homomorphism_type (
    enum HomomorphismType *ht,
    char                 *str);

int
str_to_elgamal_flavor (
    enum ElgamalFlavor *ef,
    char              *str);

int
str_to_size_t (
    size_t *output,
    char    *input);

int
general_error (
    char *error_msg);

int
openssl_error (
    char *error_msg);

int
log_base2 (
    int sec_par);

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
    uint64_t    **entries,
    int       num_entries);

int
parse_file_for_num_entries (
    int        *num_entries,
    char         *filename);

int
parse_file_for_list_entries (
    BIGNUM      **entries,
    int       num_entries,
    char        *filename);

int
cstr_to_hex (
    char  **cstr,
    size_t   len);

char *
pad_leading_zeros (
    char *msg);

int
serialize_bignum (
    char   **serialized,
    BIGNUM         *msg);

int
serialize_ecpoint (
    char   **serialized,
    EC_POINT       *msg,
    EC_GROUP     *group);

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
    unsigned char  **msg,
    char            *buf);

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
    int       file_descriptor,
    void                 *msg,
    char            *conf_str,
    enum MessageType    mtype,
    ...);

int
hash (
    unsigned char **output,
    void            *input,
    char    *hash_alg_name,
    size_t hash_digest_len,
    enum MessageType  type);

int
symmetric_encrypt (
    unsigned char **output,
    size_t     *output_len,
    void            *input,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType  type);

int
symmetric_decrypt (
    unsigned char **output,
    unsigned char   *input,
    int          input_len,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType  type);

#endif//_UTILS_H_
