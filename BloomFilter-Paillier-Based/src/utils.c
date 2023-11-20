#include "../hdr/utils.h"


uint64_t total_bytes = 0;

/**
 * Always returns FAILURE
 * prints a message corresponding to the error
 */
int
general_error (
    char *error_msg)
{
    perror(error_msg);
    return FAILURE;
}

void
set_security_param (
    int  *dst,
    char *src)
{
    sscanf(src, "%d", dst);
}

// get sockaddr, IPv4 or IPv6:
void *
get_in_addr (
    struct sockaddr *sa)
{
    if ( sa->sa_family == AF_INET ) {
	return &( ((struct sockaddr_in*)sa)->sin_addr );
    }
    return &( ((struct sockaddr_in6*)sa)->sin6_addr );
}

void
sigchld_handler (
    int s)
{
    // waitpid() might overwrite errno so we save and restore it.
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

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

int
parse_file_for_num_entries (
    int *num_entries,
    char   *filename)
{
    FILE *fin;
    int c, r, i = 0;

    fin = fopen(filename, "r");
    if (!fin) { return general_error("Failed to open input file"); }

    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		c = fgetc(fin);
	    } while(isdigit(c));
	    i++;
	}
    } while (!feof(fin) && !ferror(fin));
    *num_entries = i;

    r = fclose(fin);
    if (r == EOF) { return general_error("Failed to close input file"); }
    return SUCCESS;
}

int
parse_file_for_list_entries (
    paillier_plaintext_t **entries,
    int                num_entries,
    char                 *filename)
{
    FILE *fin;
    char *buf = calloc(MAX_FILE_BYTES, sizeof(char));
    int c, r;
    int entries_i = 0, buf_i = 0;

    fin = fopen(filename, "r");
    if (!fin) { return general_error("Failed to open input file"); }

    memset(buf, 0, MAX_FILE_BYTES);
    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		buf[buf_i++] = c;
		c = fgetc(fin);
	    } while (isdigit(c));
	    entries[entries_i] = paillier_plaintext_from_str(buf);
	    if (!entries[entries_i]) { return general_error("Failed to ptxt from str entries"); }
	    entries_i++;
	    memset(buf, 0, MAX_FILE_BYTES);
	    buf_i = 0;
	}
    } while (!feof(fin) && !ferror(fin));

    char *tmp_ptxt;
    for (int i = 0; i < num_entries; i++) {
	tmp_ptxt = paillier_plaintext_to_str(entries[i]);
	printf("entries[%i] = %s\n", i, tmp_ptxt);
	free(tmp_ptxt);
    }
    free(buf);
    r = fclose(fin);
    if (r == EOF) { return general_error( "Failed to close input file" ); }
    return SUCCESS;
}

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

int
serialize_ul (
    char  **serialized,
    unsigned long *msg)
{
    int r;

    *serialized = calloc(FIXED_LEN, sizeof(char));
    /* *serialized is null-terminated by this fn */
    r = snprintf(*serialized, FIXED_LEN, "%lu", *msg);
    if (!r) { return general_error("Failed to snprintf ul msg"); }
    return SUCCESS;
}

int
serialize_int (
    char **serialized,
    int          *msg)
{
    int r;

    *serialized = calloc(FIXED_LEN, sizeof(char));
    /* Fn null-terminates (*serialized) */
    r = snprintf(*serialized, FIXED_LEN, "%d", *msg);
    if (!r) { return general_error("Failed to snprintf int msg"); }
    return SUCCESS;
}

int
serialize_paillier_ptxt (
    char         **serialized,
    paillier_plaintext_t *msg)
{
    *serialized = mpz_get_str(NULL, 16, msg->m);
    if ( (!*serialized) ) { return general_error("Failed to serialize p_ptxt msg"); }
    return SUCCESS;
}

int
serialize_paillier_ctxt (
    char          **serialized,
    paillier_ciphertext_t *msg)
{
    *serialized = mpz_get_str(NULL, 16, msg->c);
    if ( !(*serialized) ) { return general_error("Failed to serialize p_ctxt msg"); }
    return SUCCESS;
}

int
serialize_paillier_pk (
    char      **serialized,
    paillier_pubkey_t *msg)
{
    /* Fn alloc's hex */
    *serialized = paillier_pubkey_to_hex(msg);
    if ( !(*serialized) ) { return general_error("Failed to serialize p_pk msg"); }
    return SUCCESS;
}

int
send_msg_length (
    int  file_descriptor,
    unsigned long length)
{
    int r;
    char *fixed_buf;
    unsigned long fixed_buf_num_bytes;

    r = serialize_ul(&fixed_buf, &length);
    if (r == 0) { r = 0; return general_error("Failed to snprintf fixed_buf"); }
    fixed_buf_num_bytes = strnlen(fixed_buf, FIXED_LEN);
    if (fixed_buf_num_bytes < FIXED_LEN) {
	fixed_buf = pad_leading_zeros(fixed_buf);
    } else {
	r = 0;
	return general_error("Increase fixed length");
    }
    /* Send UL length */
    r = send(file_descriptor, fixed_buf, FIXED_LEN, 0);
    if (r == -1) { r = 0; return general_error("Failed to send message len"); }
    free(fixed_buf);
    if (!r) { return FAILURE; }
    return SUCCESS;
}

int
send_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    int         print_flag,
    enum MessageType mtype)
{
    int r;
    char *buf;
    unsigned long buf_num_bytes;

    /* Serialize fns alloc mem for buf */
    switch( mtype ){
    case UnsignedLong:
	r = serialize_ul(&buf, (unsigned long *)msg);
	break;
    case Integer:
	r = serialize_int(&buf, (int *)msg);
	break;	
    case PaillierPlaintext:
	r = serialize_paillier_ptxt(&buf, (paillier_plaintext_t *)msg);
	break;
    case PaillierCiphertext:
	r = serialize_paillier_ctxt(&buf, (paillier_ciphertext_t *)msg);
	break;	
    case PaillierPubkey:
	r = serialize_paillier_pk(&buf, (paillier_pubkey_t *)msg);
	break;	
    default:
	r = 0;
	break;
    }
    if (!r) { return general_error("Failed to serialize msg"); }

    // Pre-send the real msg's length first
    buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
    r = send_msg_length(file_descriptor, buf_num_bytes);
    if (r == -1) { r = 0; return general_error("Failed to send_msg_length()"); }
    // Now send the real msg
    r = send(file_descriptor, buf, buf_num_bytes, 0);
    if (r == -1) { r = 0; return general_error("Failed to send()"); }
    total_bytes += r;
    if (print_flag) { printf("%s : %s\n", conf_str, buf); }
    
    free(buf);
    if (!r) { return FAILURE; }
    return SUCCESS;
}

int
recv_msg_length (
    int   file_descriptor,
    unsigned long *length)
{
    int r;
    char *fixed_buf;

    fixed_buf = calloc(FIXED_LEN + 1, sizeof(char)); 
    r = recv(file_descriptor, fixed_buf, FIXED_LEN, MSG_WAITALL);
    if (r == -1) { return general_error("Failed to recv message len"); }
    r = deserialize_ul(length, fixed_buf);
    if (!r)      { return general_error("Failed to deserialize ul"); }
    free(fixed_buf);
    return SUCCESS;
}

int
deserialize_ul (
    unsigned long *msg,
    char          *buf)
{
    int r;

    r = sscanf(buf, "%lu", msg);
    if( r==EOF ){ return general_error("Failed to sscanf ul"); }
    return SUCCESS;
}

int
deserialize_int (
    int  *msg,
    char *buf)
{
    int r;

    r = sscanf(buf, "%d", msg);
    if( r==EOF ){ return general_error("Failed to sscanf int"); }
    return SUCCESS;
}

int
deserialize_paillier_ptxt (
    paillier_plaintext_t **msg,
    char                  *buf)
{
    *msg = paillier_plaintext_from_str(buf);
    if (!msg) { return general_error("Failed str2p_ptxt buf"); }
    return SUCCESS;
}

int
deserialize_paillier_ctxt (
    paillier_ciphertext_t **msg,
    char                   *buf)
{
    *msg = paillier_ciphertext_from_bytes(buf, strnlen(buf, MAX_MSG_LEN));
    if (!msg) { return general_error("Failed bytes2p_ctxt buf"); }
    return SUCCESS;
}

int
deserialize_paillier_pk (
    paillier_pubkey_t **msg,
    char               *buf)
{
    /* Fn alloc's ppk */
    *msg = paillier_pubkey_from_hex( buf );
    if ( !(*msg) ) { return general_error("Failed hex2ppk"); }
    return SUCCESS;
}

int
recv_msg (
    int    file_descriptor,
    void              *msg,
    char         *conf_str,
    int         print_flag,
    enum MessageType mtype)
{
    int r;
    char *buf;
    unsigned long buf_num_bytes;

    buf = calloc(MAX_MSG_LEN, sizeof(char));
    r = recv_msg_length(file_descriptor, &buf_num_bytes);
    if (r == -1) { r = 0; return general_error("Failed to recv msg length"); }
    r = recv(file_descriptor, buf, buf_num_bytes, MSG_WAITALL);
    if (r == -1) { r = 0; return general_error("Failed to recv msg"); }
    buf[r] = '\0';
    if (print_flag) { printf("%s %s\n", conf_str, buf); }

    /* Deserialize buf into msg */
    switch (mtype) {
    case UnsignedLong:
	r = deserialize_ul((unsigned long *)msg, buf);
	break;	
    case Integer:
	r = deserialize_int((int *)msg, buf);
	break;
    case PaillierPlaintext:
	r = deserialize_paillier_ptxt((paillier_plaintext_t **)msg, buf);
	break;
    case PaillierCiphertext:
	r = deserialize_paillier_ctxt((paillier_ciphertext_t **)msg, buf);
	break;
    case PaillierPubkey:
	r = deserialize_paillier_pk((paillier_pubkey_t **)msg, buf);
	break;	
    default:
	r = 0;
	break;
    }
    if (!r) { return general_error("Failed to deserialize buf"); }

    free(buf);
    if (!r) { return FAILURE; }
    return SUCCESS;
}
