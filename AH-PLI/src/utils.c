#include "../hdr/utils.h"


uint64_t total_bytes = 0;

// get sockaddr, IPv4 or IPv6:
void *
get_in_addr (struct sockaddr *sa)
{
    if ( sa->sa_family == AF_INET ) {
	return &( ((struct sockaddr_in*)sa)->sin_addr );
    }
    return &( ((struct sockaddr_in6*)sa)->sin6_addr );
}

void
sigchld_handler (int s)
{
    // waitpid() might overwrite errno so we save and restore it.
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void
hardcode_socket_parameters (struct addrinfo **service_info,
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
set_socket_and_bind (int    *socket_file_descriptor,
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
set_socket_and_connect (int    *socket_file_descriptor,
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
start_server(int socket_file_descriptor,
	     const int backlog)
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
reap_all_dead_processes (void)
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
accept_connection (int listener_sockfd)
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
 * Dummy list generator
 * Generates a list 'num_entries' in length
 * and equal to 1,2,...,num_entries-2,
 * but makes the final element random
 * Note if you want to add error handling it
 * would be on the printf functions...but not
 * sure that I care to.
 */
int
generate_list_entries (uint64_t    **entries,
		       int       num_entries)
{
    srand (time(NULL));
    for (int i = 0; i < num_entries-1 ; i++) {
	(*entries)[i] = (uint64_t)i + (uint64_t)1ULL;
	printf("entries[%i] = %" PRIu64 "\n", i, (*entries)[i]);
    }
    (*entries)[num_entries-1] = ((uint64_t)rand()) % ((1ULL) << 32);
    printf("entries[%i] = %" PRIu64 "\n", num_entries-1, (*entries)[num_entries-1]);
    return SUCCESS;
}

int
parse_file_for_num_entries (int       *num_entries,
			    char         *filename)
{
    FILE *fin;
    int c, r, i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	perror("Failed to open input file");
	return FAILURE;
    }

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
    if (r == EOF) {
	perror("Failed to close input file");
	return FAILURE;
    }
    return SUCCESS;
}

int
parse_file_for_list_entries (uint64_t    **entries,
			     int       num_entries,
			     char        *filename)
{
    FILE *fin;
    char buf[MAX_FILE_BYTES];
    int c, r;
    int entries_i = 0, buf_i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	perror("Failed to open input file");
	return FAILURE;
    }

    memset(buf, 0, sizeof(buf));
    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		buf[buf_i++] = c;
		c = fgetc(fin);
	    } while(isdigit(c));
	    r = sscanf(buf, "%llu", &(*entries)[entries_i]);
	    entries_i++;
	    if (r == EOF) {
		perror("Failed to sscanf buf into entries");
		return FAILURE;
	    }
	    memset(buf, 0, sizeof(buf));
	    buf_i = 0;
	}
    } while (!feof(fin) && !ferror(fin));

    for (int i = 0; i < num_entries; i++) {
	printf("entries[%i] = %" PRIu64 "\n", i, (*entries)[i]);
    }
    r = fclose(fin);
    if (r == EOF) {
	perror("Failed to close input file");
	return FAILURE;
    }
    return SUCCESS;
}

char *
pad_leading_zeros (char *msg)
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
send_bn_msg_length (int file_descriptor,
		    unsigned long length)
{
    int r;
    char *fixed_buf;
    unsigned long fixed_buf_num_bytes;

    fixed_buf = calloc(FIXED_LEN, sizeof(char));
    /* fixed_buf is null-terminated by this fn */
    r = snprintf(fixed_buf, FIXED_LEN, "%lu", length);
    if (r == 0) {
	perror("Failed to snprintf fixed_buf");
	close(file_descriptor);
	free(fixed_buf);
	return FAILURE;
    }
    fixed_buf_num_bytes = strnlen(fixed_buf, FIXED_LEN);
    if (fixed_buf_num_bytes < FIXED_LEN) {
	fixed_buf = pad_leading_zeros(fixed_buf);
    } else {
	perror("Increase fixed length");
	close(file_descriptor);
	free(fixed_buf);
	return FAILURE;
    }
    r = send(file_descriptor, fixed_buf, FIXED_LEN, 0);
    if (r == -1) {
	perror("Failed to send bn message len");
	close(file_descriptor);
	free(fixed_buf);
	return FAILURE;
    }
    return SUCCESS;
}

int
send_bn_msg (int file_descriptor,
	     BIGNUM     *message,
	     char      *conf_str)
{
    int r;
    char *buf;
    unsigned long buf_num_bytes;

    // buf is null-terminated and
    // malloc'd by this fn
    buf = BN_bn2hex(message);
    if (!buf) {
	perror("Error bn2hex bn message");
	close(file_descriptor);
	free(buf);
	return FAILURE;
    }

    buf_num_bytes = strnlen(buf, MAX_MSG_LEN);
    r = send_bn_msg_length(file_descriptor, buf_num_bytes);
    if (r == -1) {
	perror("Failed to send bn message length");
	close(file_descriptor);
	free(buf);
	return FAILURE;
    }
    r = send(file_descriptor, buf, buf_num_bytes, 0);
    if (r == -1) {
	perror("Failed to send bn message");
	close(file_descriptor);
	free(buf);
	return FAILURE;
    }
    total_bytes += r;    
    printf("%s %s\n", conf_str, buf);
    free(buf);
    return SUCCESS;
}

int
recv_bn_msg_length (int file_descriptor,
		    unsigned long *length)
{
    int r;
    char *fixed_buf;

    fixed_buf = calloc(FIXED_LEN+1, sizeof(char));
    r = recv(file_descriptor, fixed_buf, FIXED_LEN, 0);
    if (r  == -1) {
	perror("Failed to recv bn message");
	close(file_descriptor);
	return FAILURE;
    }
    r = sscanf(fixed_buf, "%lu", length);
    if (r == EOF) {
	perror("Failed to sscanf msg_buffer_len");
	close(file_descriptor);
	return FAILURE;
    }
    free(fixed_buf);
    return SUCCESS;
}

/**
 *
 */
int
recv_bn_msg (int file_descriptor,
	     BIGNUM     *message,
	     char      *conf_str)
{
    int r;
    char *buf;
    unsigned long buf_num_bytes;

    buf = calloc(MAX_MSG_LEN, sizeof(char));
    r = recv_bn_msg_length(file_descriptor, &buf_num_bytes);
    if (r == -1) {
	perror("Failed to recv bn message length");
	close(file_descriptor);
	free(buf);
	return FAILURE;
    }
    r = recv(file_descriptor, buf, buf_num_bytes, 0);
    if ( r  == -1 ) {
	perror("Failed to recv bn message");
	close(file_descriptor);
	return FAILURE;
    }
    buf[r] = '\0';
    printf("%s %s\n", conf_str, buf);
    r = BN_hex2bn(&message, buf);
    if (!r) {
	perror("Failed hex2bn hex buf");
	close(file_descriptor);
	return FAILURE;
    }
    free(buf);
    return SUCCESS;
}
