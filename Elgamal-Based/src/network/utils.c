#include <netdb.h>                      // struct sockaddr
#include <openssl/bn.h>		        // BIGNUM
#include "../../hdr/input-args/utils.h" // enum PartyType
#include <openssl/ec.h>		        // EC_POINT
#include "../../hdr/macros.h"           // FIXED_LEN
#include "../../hdr/network/utils.h"
#include <errno.h>                 // errno
#include "../../hdr/error/utils.h" // openssl_error()
#include <unistd.h>		   // close()
#include <arpa/inet.h>		   // inet_ntop()
#include <signal.h>		   // sigemptyset()
#include <sys/wait.h>              // waitpid()
#ifdef __linux__                   // Check if the platform is linux
#include <bsd/string.h>            // strlcpy()
#endif



/* Should this be in logging/utils.c or here? */
size_t total_bytes = 0;

// get sockaddr, IPv4 or IPv6:
/**
 *
 */
void *
get_in_addr (
    struct sockaddr *sa)
{
    if ( sa->sa_family == AF_INET ) {
	return &( ((struct sockaddr_in*)sa)->sin_addr );
    }
    return &( ((struct sockaddr_in6*)sa)->sin6_addr );
}

/**
 *
 */
void
sigchld_handler (
    int s)
{
    // waitpid() might overwrite errno so we save and restore it.
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/**
 *
 */
void
hardcode_socket_parameters (
    struct addrinfo **service_info,
    const char        *port_number,
    enum PartyType            type,
    char                 *hostname)
{
    int r;
    struct addrinfo hints; // field values for the listener socket
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (type == SERVER) {
	// Use my IP address
	hints.ai_flags = AI_PASSIVE;
    }
    r = getaddrinfo(hostname, port_number, &hints, service_info);
    if (r) {// getaddrinfo gives 0 on success
	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
	exit(r);
    }
}

/**
 *
 */
void
set_socket_and_bind (
    int    *socket_file_descriptor,
    struct addrinfo **service_info)
{
    int r;
    int yes = 1;
    // Loop through all the results and bind to the first one we can.
    struct addrinfo *p;
    for (p = *service_info; p != NULL; p = p->ai_next) {
	*socket_file_descriptor = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	if (*socket_file_descriptor == -1) {
	    perror("server: Failed to create socket");
	    continue;
	}
	r = setsockopt(*socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if (r == -1 ) {
	    close(*socket_file_descriptor);
	    perror("setsockopt");
	    exit(1);
	}
	r = bind(*socket_file_descriptor, p->ai_addr, p->ai_addrlen);
	if ( r == -1 ) {
	    close(*socket_file_descriptor);
	    perror("server: Failed during bind attempt");
	    continue;
	}
	break;
    }
    if (!p) {
	close(*socket_file_descriptor);
	perror("server: Failed to bind");
	exit(1);
    }
}

/**
 *
 */
void
set_socket_and_connect (
    int    *socket_file_descriptor,
    struct addrinfo **service_info)
{
    int r;
    char ip_addr[INET6_ADDRSTRLEN];
    struct sockaddr *addr;
    struct addrinfo *p;
    // Loop through all the results and connect to the first one we can
    for (p = *service_info; p != NULL; p = p->ai_next) {
	*socket_file_descriptor = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	if (*socket_file_descriptor == -1) {
	    perror("client: Failed to create socket");
	    continue;
	}
	r = connect(*socket_file_descriptor, p->ai_addr, p->ai_addrlen);
	if ( r == -1 ) {
	    close(*socket_file_descriptor);
	    perror("client: Failed during connect attempt");
	    continue;
	}
	break;
    }
    if (!p) {
	close(*socket_file_descriptor);
	perror("client: Failed to connect");
	exit(1);
    }
    addr = (struct sockaddr *)p->ai_addr;
    inet_ntop(p->ai_family, get_in_addr(addr),
	      ip_addr, sizeof(ip_addr));
    printf("client: connecting to %s\n", ip_addr);
}

/**
 * The backlog parameter defines the maximum length for the queue of pending connections.  If a
 * connection request arrives with the queue full, the client may receive an error with an
 * indication of ECONNREFUSED.  Alternatively, if the underlying protocol supports retransmission,
 * the request may be ignored so that retries may succeed.
 */
void
start_server (
    int socket_file_descriptor,
    const int          backlog)
{
    int r;
    r = listen(socket_file_descriptor, backlog);
    if (r == -1) {
	close(socket_file_descriptor);
	perror("server: Failed to exec listen()");
	exit(1);
    }
}

/**
 * Review the beeg guide for why we need this function
 */
void
reap_all_dead_processes (
    void)
{
    struct sigaction sa;

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if ( sigaction(SIGCHLD, &sa, NULL) == -1 ) {
	perror("sigaction");
	exit(1);
    }
}

/**
 *
 */
int
accept_connection (
    int listener_sockfd)
{
    int new_file_descriptor;
    socklen_t sin_size;
    struct sockaddr_storage client_addr; //client's addr
    struct sockaddr *addr;
    char ip_addr[INET6_ADDRSTRLEN];
    /* socklen_t sin_size = sizeof (their_addr); */
    sin_size = sizeof (struct sockaddr_storage);
    addr = (struct sockaddr *)&client_addr;
    new_file_descriptor = accept(listener_sockfd, addr, &sin_size);

    if (new_file_descriptor != -1) {
	inet_ntop(client_addr.ss_family, get_in_addr(addr), ip_addr, sizeof(ip_addr));
	printf("server: connection from %s\n", ip_addr);
    } else {
	//perror("No connection to accept");
    }
    return new_file_descriptor;
}

/**
 *
 */
char *
pad_leading_zeros (
    char *msg)
{
    int r;
    char *buffer;
    unsigned long pad_len;
    unsigned long msg_len;

    msg_len = strnlen(msg, FIXED_LEN);
    buffer = calloc(FIXED_LEN+1, sizeof(char));
    pad_len = FIXED_LEN - msg_len;
    buffer = memset(buffer, '0', pad_len);
    r = strlcpy(buffer + pad_len, msg, msg_len+1);
    if (r < msg_len) {
	perror("Failed to strlcpy msg");
	free(buffer);
	return NULL;
    }
    free(msg);
    return buffer;
}

/**
 *
 */
int
serialize_bignum (
    char   **serialized,
    BIGNUM         *msg)
{
    // buf is null-terminated and
    // malloc'd by this fn
    *serialized = BN_bn2hex(msg);
    if (!*serialized) {
	free(*serialized);
	return openssl_error("Error bn2hex msg");
    }
    return SUCCESS;
}

/**
 *
 */
int
serialize_ecpoint (
    char   **serialized,
    EC_POINT       *msg,
    EC_GROUP     *group)
{
    BN_CTX *ctx = BN_CTX_new();
    // *serialized is malloc'd by this fn
    // to a length sufficient for the hex representation
    *serialized = EC_POINT_point2hex(group, msg, POINT_CONVERSION_UNCOMPRESSED, ctx);
    BN_CTX_free(ctx);
    if (!*serialized) {
	return openssl_error("Failed to point2hex msg");
    }
    return SUCCESS;
}

/**
 *
 */
int
serialize_int (
    char **serialized,
    int          *msg)
{
    int r;

    *serialized = calloc(FIXED_LEN, sizeof(char));
    /* *serialized is null-terminated by this fn */
    r = snprintf(*serialized, FIXED_LEN, "%d", *msg);
    if (!r) {
	return general_error("Failed to snprintf msg");
    }
    return SUCCESS;
}

/**
 *
 */
int
serialize_size_t (
    char **serialized,
    size_t       *msg)
{
    int r;

    *serialized = calloc(FIXED_LEN, sizeof(char));
    /* *serialized is null-terminated by this fn */
    r = snprintf(*serialized, FIXED_LEN, "%lu", *msg);
    if (!r) {
	return general_error("Failed to snprintf msg");
    }
    return SUCCESS;
}

/**
 *
 */
int
serialize_uchar (
    char  **serialized,
    unsigned char *msg,
    size_t         len)
{
    *serialized = calloc(len, sizeof(char));
    if (!*serialized) { return general_error("Failed to alloc *serialized"); }
    for (int i = 0; i < len; i++) {
	(*serialized)[i] = (char)msg[i];
    }
    return SUCCESS;
}

/**
 *
 */
int
send_msg_length (
    int file_descriptor,
    unsigned long length)
{
    int r;
    char *fixed_buf;
    unsigned long fixed_buf_num_bytes;
    size_t bytes_sent = 0;

    /* Serialize UL length */
    fixed_buf = calloc(FIXED_LEN, sizeof(char));
    /* fixed_buf is null-terminated by this fn */
    r = snprintf(fixed_buf, FIXED_LEN, "%lu", length);
    if (r == 0) { r = 0; return general_error("Failed to snprintf fixed_buf"); }
    fixed_buf_num_bytes = strnlen(fixed_buf, FIXED_LEN);
    if (fixed_buf_num_bytes < FIXED_LEN) {
	fixed_buf = pad_leading_zeros(fixed_buf);
    } else {
	r = 0;
	return general_error("Increase fixed length");
    }
    /* Send UL length */
    while (bytes_sent < FIXED_LEN) {
	r = send(file_descriptor, fixed_buf + bytes_sent, FIXED_LEN - bytes_sent, 0);
	if (r == -1) { r = 0; return general_error("Failed to send message len"); }
	bytes_sent += r;
    }
    free(fixed_buf);
    return SUCCESS;
}

/**
 *
 */
int
send_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    enum MessageType mtype,
    ...)
{
    int r;
    char *buf;
    size_t buf_num_bytes;
    va_list args_ptr;
    size_t bytes_sent = 0;

    /* Serialize fns alloc mem for buf */
    switch (mtype) {
    case Integer:
	r = serialize_int(&buf, (int *)msg);
	buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
	break;
    case SizeT:
	r = serialize_size_t(&buf, (size_t *)msg);
	buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
	break;
    case UnsignedChar:
	va_start(args_ptr, mtype);
	buf_num_bytes = va_arg(args_ptr, size_t);
	r = serialize_uchar(&buf, (unsigned char *)msg, buf_num_bytes);
	va_end(args_ptr);
	break;
    case Bignum:
	r = serialize_bignum(&buf, (BIGNUM *)msg);
	buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
	break;
    case Ecpoint:
	va_start(args_ptr, mtype);
	EC_GROUP *g = va_arg(args_ptr, EC_GROUP *);
	r = serialize_ecpoint(&buf, (EC_POINT *)msg, g);
	va_end(args_ptr);
	buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
	break;
    default:
	r = 0;
	break;
    }
    if (!r) { return general_error("Failed to serialize msg"); }
    // Pre-send the real msg's length first
    r = send_msg_length(file_descriptor, buf_num_bytes);
    if (r == -1) { r = 0; return general_error("Failed to send msg length"); }
    // Now send the real msg
    while (bytes_sent < buf_num_bytes) {
	r = send(file_descriptor, buf + bytes_sent, buf_num_bytes - bytes_sent, 0);
	if (r == -1) { r = 0; return general_error("Failed to send msg"); }
	bytes_sent += r;
    }
    total_bytes += bytes_sent;
    /* if (mtype == UnsignedChar) { */
    /* 	printf("%s ", conf_str); */
    /* 	for (int i = 0; i < buf_num_bytes; i++) { */
    /* 	    printf("%02x ", buf[i]); */
    /* 	} */
    /* 	printf("\n"); */
    /* } else { */
    /* 	printf("%s %s\n", conf_str, buf); */
    /* } */

    free(buf);
    return SUCCESS;
}

/**
 *
 */
int
recv_msg_length (
    int   file_descriptor,
    unsigned long *length)
{
    int r;
    char *fixed_buf;

    fixed_buf = calloc(FIXED_LEN+1, sizeof(char));
    r = recv(file_descriptor, fixed_buf, FIXED_LEN, 0);
    if (r == -1) { r = 0; return general_error("Failed to recv message len"); }
    r = sscanf(fixed_buf, "%lu", length);
    if (r == EOF) { r = 0; return general_error("Failed to sscanf msg_buffer_len"); }
    free(fixed_buf);
    return SUCCESS;
}

/**
 *
 */
int
deserialize_int (
    int  *msg,
    char *buf)
{
    int r;
    r = sscanf(buf, "%d", msg);
    if (r == EOF) {
	return general_error("Failed to sscanf msg_buffer_len");
    }
    return SUCCESS;
}

/**
 *
 */
int
deserialize_size_t (
    size_t *msg,
    char   *buf)
{
    int r;
    r = sscanf(buf, "%lu", msg);
    if (r == EOF) {
	return general_error("Failed to sscanf msg_buffer_len");
    }
    return SUCCESS;
}

/**
 *
 */
int
deserialize_uchar (
    unsigned char **msg,
    char           *buf,
    size_t          len)
{
    for (int i = 0; i < len; i++) {
	/* snprintf((char *)&(*msg)[i], len, "%02x", buf[i]);	 */
	(*msg)[i] = (unsigned char)buf[i];
    }
    return SUCCESS;
}

/**
 *
 */
int
deserialize_bignum (
    BIGNUM **msg,
    char    *buf)
{
    int r;
    r = BN_hex2bn(msg, buf);
    if (!r) {
	return openssl_error("Failed hex2bn hex buf");
    }
    return SUCCESS;
}

/**
 *
 */
int
deserialize_ecpoint (
    EC_POINT  **msg,
    char       *buf,
    EC_GROUP *group)
{
    EC_POINT *r;
    BN_CTX *ctx = BN_CTX_new();

    r = EC_POINT_hex2point(group, buf, *msg, ctx);
    if (!r) {
	return openssl_error("Failed hex2ecpoint buf");
    }
    return SUCCESS;
}

/**
 *
 */
int
recv_msg (
    int       file_descriptor,
    void                 *msg,
    char            *conf_str,
    enum MessageType    mtype,
    ...)
{
    int r;
    char *buf;
    unsigned long buf_num_bytes;
    va_list args_ptr;

    buf = calloc(MAX_MSG_LEN, sizeof(char));
    r = recv_msg_length(file_descriptor, &buf_num_bytes);
    if (!r) { r = 0; return general_error("Failed to recv msg length"); }
    r = recv(file_descriptor, buf, buf_num_bytes, 0);
    if ( r  == -1 ) { r = 0; return general_error("Failed to recv msg"); }
    buf[r] = '\0';
    total_bytes += r;
    /* if (mtype != UnsignedChar) { */
    /* 	printf("%s %s\n", conf_str, buf); */
    /* } else { */
    /* 	printf("%s ", conf_str); */
    /* 	for (int i = 0; i < buf_num_bytes; i++) { */
    /* 	    printf("%02x ", (unsigned int)buf[i]); */
    /* 	} */
    /* 	printf("\n"); */
    /* } */

    /* Deserialize buf into msg */
    switch (mtype) {
    case Integer:
	r = deserialize_int((int *)msg, buf);
	break;
    case SizeT:
	r = deserialize_size_t((size_t *)msg, buf);
	break;
    case UnsignedChar:
	r = deserialize_uchar((unsigned char **)msg, buf, buf_num_bytes);
	break;
    case Bignum:
	r = deserialize_bignum((BIGNUM **)msg, buf);
	break;
    case Ecpoint:
	va_start(args_ptr, mtype);
	EC_GROUP *g = va_arg(args_ptr, EC_GROUP *);
	r = deserialize_ecpoint((EC_POINT **)msg, buf, g);
	va_end(args_ptr);
	break;
    default:
	r = 0;
	break;
    }
    if (!r) { return general_error("Failed to deserialize buf"); }

    free(buf);
    return SUCCESS;
}
