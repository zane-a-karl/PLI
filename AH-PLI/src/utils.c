#include "../hdr/utils.h"


size_t total_bytes = 0;

/**
 *
 */
int
parse_input_args (
    InputArgs        *ia,
    int             argc,
    char          **argv,
    enum PartyType party)
{
    int r;
    int c;

    /* Setup ia defaults */
    ia->hostname  = "localhost";
    ia->pmeth     = PLI;
    ia->eflav     = ECEG;
    ia->htype     = AH;
    ia->secpar    = 64UL;
    ia->threshold = 0;
    ia->client_filename = "input/client.txt";
    ia->server_filename = "input/server.txt";
    if (party == CLIENT) {
	/* TODO: use stdlib system() to call ./setup_default_client_file.sh */
	r = parse_file_for_num_entries(&ia->num_entries, ia->client_filename);
    } else {
	/* TODO: use stdlib system() to call ./setup_default_server_file.sh */	
	r = parse_file_for_num_entries(&ia->num_entries, ia->server_filename);
    }
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    int option_index = 0;
    static struct option long_options[] =
	{
	    {"hostname",           required_argument, NULL, 'h'},
	    {"pli-method",         required_argument, NULL, 'p'},
	    {"elgamal-flavor",     required_argument, NULL, 'e'},
	    {"homomorphism-type",  required_argument, NULL, 'm'},
	    {"security-parameter", required_argument, NULL, 'y'},
	    {"list-length",        required_argument, NULL, 'n'},	    
	    {"threshold",          required_argument, NULL, 't'},
	    {"client-filename",    required_argument, NULL, 'c'},
	    {"server-filename",    required_argument, NULL, 's'},
	    {0, 0, 0, 0}
	};
    while (1) {
	c = getopt_long(argc, argv, "h:p:e:m:y:n:t:c:s:", long_options, &option_index);
	/* Detect the end of the options. */
	if (c == -1) { break; }
	switch (c) {
        case 0:
	    if (long_options[option_index].flag != 0) { break; }
	    printf("option %s", long_options[option_index].name);
	    if (optarg) {
		printf(" with arg %s", optarg);
	    }
	    printf("\n");
	    break;
        case 'h':
	    printf("option -h with value `%s'\n", optarg);
	    ia->hostname = optarg;
	    break;
        case 'p':
	    printf("option -p with value `%s'\n", optarg);
	    r = str_to_pli_method(&ia->pmeth, optarg);
	    if (!r) { return general_error("Failed to parse pli method"); }
	    break;
        case 'e':
	    printf("option -e with value `%s'\n", optarg);
	    r = str_to_elgamal_flavor(&ia->eflav, optarg);
	    if (!r) { return general_error("Failed to parse elgamal flavor"); }
	    break;
        case 'm':
	    printf("option -m with value `%s'\n", optarg);
	    r = str_to_homomorphism_type(&ia->htype, optarg);
	    if (!r) { return general_error("Failed to parse homomorphism type"); }
	    break;
        case 'y':
	    printf("option -y with value `%s'\n", optarg);
	    r = str_to_size_t(&ia->secpar, optarg);
	    if (!r) { return general_error("Failed to parse secpar"); }
	    break;
        case 'n':
	    printf("option -n with value `%s'\n", optarg);
	    size_t n = 0;
	    r = str_to_size_t(&n, optarg);
	    if (!r) { return general_error("Failed to parse list_len"); }
	    if (n != ia->num_entries) { return general_error(""); }
	    break;	    
        case 't':
	    printf("option -t with value `%s'\n", optarg);
	    r = str_to_size_t(&ia->threshold, optarg);
	    if (!r) { return general_error("Failed to parse threshold"); }
	    break;
        case 'c':
	    printf("option -c with value `%s'\n", optarg);
	    ia->client_filename = optarg;
	    break;
        case 's':
	    printf("option -s with value `%s'\n", optarg);
	    ia->server_filename = optarg;
	    break;
        case '?':
	    /* getopt_long returns its own error message */
        default:
	    printf("Usage: %s", argv[0]);
	    printf("--hostname           -h <hostname>\n");
	    printf("--pli-method         -p <pli method>\n");
	    printf("--elgamal-flavor     -e <EG or ECEG>\n");
	    printf("--homomorphism-type  -m <MH or AH>\n");
	    printf("--security-parameter -y <security parameter>\n");
	    printf("--list-len           -n <list-len>\n");	    
	    printf("--threshold          -t <threshold>\n");
	    printf("--client-filename    -c <client-filename>\n");
	    printf("--server-filename    -s <server-filename>\n");
	    return general_error("Failed to follow correct program usage");
        } /* switch */
    } /* while */

    /* Print any remaining command line arguments (not options). */
    if (optind < argc) {
	printf("non-option ARGV-elements: ");
	while (optind < argc) {
	    printf("%s ", argv[optind++]);
	}
	putchar('\n');
    }
    if ( (ia->pmeth == t_PLI || ia->pmeth == t_PLI_ca || ia->pmeth == t_PLI_x) && !ia->threshold ) {
	return general_error("Failed to match PLI method with threshold");
    }
    if (ia->secpar < 8) {
	return general_error("Failed provide meaningful security parameter");
    }
    if (ia->threshold > ia->num_entries || ia->threshold < 1) {
	return general_error("Failed to set meaningful threshold");
    }    
    if ( ia->eflav == ECEG && ia->htype == MH ) {
	return general_error("Library does not yet implement ECEG with MH");
    }

    return SUCCESS;
}

/**
 *
 */
int
str_to_pli_method (
    enum PliMethod *pm,
    char          *str)
{
    const int max_pmeth_str_len = 9;
    if ( 0 == strncmp(str, "PLI", max_pmeth_str_len) ) {
	*pm = PLI;
    } else if ( 0 == strncmp(str, "PLIca", max_pmeth_str_len) ) {
	*pm = PLI_ca;
    } else if ( 0 == strncmp(str, "tPLI", max_pmeth_str_len) ) {
	*pm = t_PLI;
    } else if ( 0 == strncmp(str, "PLIx", max_pmeth_str_len) ) {
	*pm = PLI_x;
    } else if ( 0 == strncmp(str, "tPLIca", max_pmeth_str_len) ) {
	*pm = t_PLI_ca;
    } else if ( 0 == strncmp(str, "tPLIx", max_pmeth_str_len) ) {
	*pm = t_PLI_x;
    } else {
	printf("Error: Input must match one of {PLI, PLIca, tPLI, PLIx, tPLIca, tPLIx} exactly\n");
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_homomorphism_type (
    enum HomomorphismType *ht,
    char                 *str)
{
    const int max = 3;
    for (int i = 0; i < strnlen(str, max); i++) {
	str[i] = toupper(str[i]);
    }
    if ( 0 == strncmp(str, "AH", max) ) {
	*ht = AH;
    } else if ( 0 == strncmp(str, "MH", max) ) {
	*ht = MH;
    } else {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_elgamal_flavor (
    enum ElgamalFlavor *ef,
    char              *str)
{
    const int max = 10;
    for (int i = 0; i < strnlen(str, max); i++) {
	str[i] = tolower(str[i]);
    }
    printf("the elfav = %s\n", str);
    if ( 0 == strncmp(str, "elgamal", max) ||
	 0 == strncmp(str, "eg", max)) {
	*ef = EG;
    } else if ( 0 == strncmp(str, "ecelgamal", max) ||
		0 == strncmp(str, "eceg", max)) {
	*ef = ECEG;
    } else {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_size_t (
    size_t *output,
    char    *input)
{
    int r = sscanf(input, "%lu", output);
    if (!r) { return FAILURE; }
    return SUCCESS;
}

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

/**
 * Always returns FAILURE
 * prints a message corresponding to the
 * openssl error
 */
int
openssl_error (
    char *error_msg)
{
    unsigned long error_code = ERR_get_error();
    perror(error_msg);
    perror(ERR_error_string(error_code, NULL));
    return FAILURE;
}

/**
 *
 */
int
log_base2 (
    int sec_par)
{
    int result = -1;
    while (sec_par > 0) {
	sec_par >>= 1;
	result++;
    }
    return result;
}

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
 * Dummy list generator
 * Generates a list 'num_entries' in length
 * and equal to 1,2,...,num_entries-2,
 * but makes the final element random
 * Note if you want to add error handling it
 * would be on the printf functions...but not
 * sure that I care to.
 */
int
generate_list_entries (
    uint64_t **entries,
    int    num_entries)
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

/**
 *
 */
int
parse_file_for_num_entries (
    size_t *num_entries,
    char      *filename)
{
    FILE *fin;
    int c, r, i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	return general_error("Failed to open input file");
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
	return general_error("Failed to close input file");
    }
    return SUCCESS;
}

/**
 *
 */
int
parse_file_for_list_entries (
    BIGNUM      **entries,
    int       num_entries,
    char        *filename)
{
    FILE *fin;
    char *buf = calloc(MAX_FILE_BYTES, sizeof(char));
    int c, r;
    int entries_i = 0, buf_i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	return general_error("Failed to open input file");
    }

    memset(buf, 0, MAX_FILE_BYTES);
    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		buf[buf_i++] = c;
		c = fgetc(fin);
	    } while(isdigit(c));
	    entries[entries_i] = BN_new();
	    if (!entries[entries_i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
	    r = BN_dec2bn(&entries[entries_i], buf);
	    if (!r) { return openssl_error("Failed to dec2bn entries"); }
	    entries_i++;
	    memset(buf, 0, MAX_FILE_BYTES);
	    buf_i = 0;
	}
    } while (!feof(fin) && !ferror(fin));

    /* for (int i = 0; i < num_entries; i++) { */
    /* 	printf("entries[%i] = ", i); BN_print_fp(stdout, entries[i]); printf("\n"); */
    /* } */
    free(buf);
    r = fclose(fin);
    if (r == EOF) {
	return general_error("Failed to close input file");
    }
    return SUCCESS;
}

/**
 *
 */
int
cstr_to_hex (
    char **cstr,
    size_t  len)
{
    size_t hex_len = 2*len;
    char hex[hex_len];
    for (int i = 0; i < len; i++) {
	printf("(*cstr)[i] = %x\n", (*cstr)[i]);
	printf("((*cstr)[i] >> 4) & 0xf0 = %x\n", ((*cstr)[i] >> 4) & 0x0f);
	hex[2*i]     = ((*cstr)[i] >> 4) & 0x0f;

	hex[2*i + 1] = (*cstr)[i] & (0xf0 >> 4);
	printf("(*cstr)[i] & (0xf0 >> 4) = %x\n", (*cstr)[i] & (0xf0 >> 4));
    }
    *cstr = realloc((*cstr), hex_len * sizeof(char));
    for (int i = 0; i < hex_len; i++) {
	printf("%x", hex[i]);
	snprintf(&(*cstr)[i], 1, "%x", hex[i]);
    }
    printf("\n");
    printf("%s\n", (*cstr));
    return SUCCESS;
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
    if (!r) {
	return FAILURE;
    }
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
    if (!r) {
	return FAILURE;
    }
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
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 * Hashes an input into an output via the alg specified by the name given by
 * $openssl list -digest-algorithms
 */
int
hash (
    unsigned char **output,
    void            *input,
    char    *hash_alg_name,
    size_t hash_digest_len,
    enum MessageType mtype,
    ...)
{
    int r;
    size_t data_len = 0;
    unsigned char *data;
    unsigned int output_len;
    va_list args_ptr;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_MD *hash_alg = EVP_MD_fetch(NULL, hash_alg_name, NULL);
    if (!hash_alg) { return openssl_error("Failed to fetch hash_alg"); }
    r = EVP_DigestInit_ex(ctx, hash_alg, NULL);
    if (!r) { return openssl_error("Failed to init hash_alg"); }

    /* Parse 'void *input' into 'unsigned char *data' */
    switch (mtype) {
    case Bignum:
	data_len = BN_num_bytes((BIGNUM *)input);
	data = calloc(data_len, sizeof(*data));
	r = BN_bn2bin((BIGNUM *)input, data);
	if (!r) { return openssl_error("Failed to bn2bin input"); }
	break;
    case Ecpoint:
	va_start(args_ptr, mtype);	
	EC_GROUP *group = va_arg(args_ptr, EC_GROUP *);
	/* Calling this fn with NULL in the output argument buf gives us the length */
	data_len = EC_POINT_point2oct(group, (EC_POINT *)input,
				      POINT_CONVERSION_UNCOMPRESSED,
				      NULL, 0, NULL);
	data = calloc(data_len, sizeof(*data));	
	data_len = EC_POINT_point2oct(group, (EC_POINT *)input,
				      POINT_CONVERSION_UNCOMPRESSED,
				      data, data_len, NULL);
	va_end(args_ptr);		
	if (data_len == 0) { return openssl_error("Failed to point2oct input"); }
	break;	
    default:
	break;
    }

    r = EVP_DigestUpdate(ctx, data, data_len); /* strlen((char *)data)); */
    if (!r) { return openssl_error("Failed to hash data"); }

    *output = calloc(hash_digest_len, sizeof(unsigned char));
    r = EVP_DigestFinal_ex(ctx, *output, &output_len);
    if (!r) { return openssl_error("Failed to hash leftover data"); }

    // Print the hash value
    /* printf("Hash Output: "); */
    /* for (unsigned int i = 0; i < output_len; i++) { */
    /*     printf("%02x", (*output)[i]); */
    /* } */
    /* printf("\n"); */

    free(data);
    EVP_MD_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Encrypts an input into an output via the alg specified by the name given by
 * $openssl list -cipher-algorithms
 */
int
symmetric_encrypt (
    unsigned char **output,
    size_t     *output_len,
    void            *input,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType mtype)
{
    int r;
    int data_len;
    unsigned char *data;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_CIPHER *se_alg = EVP_CIPHER_fetch(NULL, se_alg_name, NULL);
    if (!se_alg) { return openssl_error("Failed to fetch se_alg"); }
    r = EVP_EncryptInit(ctx, se_alg, key, iv);
    if (!r) { return openssl_error("Failed to init se_alg"); }

    /* Parse 'void *input' into 'unsigned char *data' */
    switch (mtype) {
    case Bignum:
	data_len = EVP_MAX_MD_SIZE;
	data = calloc(data_len, sizeof(*data));
	r = BN_bn2bin((BIGNUM *)input, data);
	if (!r) { return openssl_error("Failed to bn2bin input"); }
	break;
    default:
	return openssl_error("Input unknown message typename");
	break;
    }

    *output_len = 0;
    *output = calloc(MAX_MSG_LEN, sizeof(unsigned char));
    r = EVP_EncryptUpdate(ctx, *output, &len, data, strlen((char *)data));
    if (!r) { return openssl_error("Failed to encrypt plaintext data"); }
    *output_len += len;

    r = EVP_EncryptFinal_ex(ctx, *output + *output_len, &len);
    if (!r) { return openssl_error("Failed to encrypt leftovers"); }
    *output_len += len;

    // Print ciphertext
    /* printf("Ciphertext: "); */
    /* for (int i = 0; i < *output_len; i++) */
    /*     printf("%02x ", (*output)[i]); */
    /* printf("\n"); */

    free(data);
    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Decrypts an input into an output via the alg specified by the name given by
 * $openssl list -cipher-algorithms
 */
int
symmetric_decrypt (
    unsigned char **output,
    unsigned char   *input,
    int          input_len,
    unsigned char     *key,
    unsigned char      *iv,
    char      *se_alg_name,
    enum MessageType mtype)
{
    int r;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return openssl_error("Failed to alloc ctx"); }
    EVP_CIPHER *se_alg = EVP_CIPHER_fetch(NULL, se_alg_name, NULL);
    if (!se_alg) { return openssl_error("Failed to fetch se_alg"); }
    r = EVP_DecryptInit(ctx, se_alg, key, iv);
    if (!r) { return openssl_error("Failed to init se_alg_name"); }

    int decryptedtext_len = 0;
    *output = calloc(MAX_MSG_LEN, sizeof(unsigned char));
    r = EVP_DecryptUpdate(ctx, *output, &len, input, input_len);
    if (!r) { return openssl_error("Failed to decrypt ctxt data"); }
    decryptedtext_len += len;

    r = EVP_DecryptFinal_ex(ctx, *output + decryptedtext_len, &len);
    if (!r) { return openssl_error("Failed to decrypt leftovers"); }
    decryptedtext_len += len;

    /* printf("Encrypted Text: "); */
    /* for (int i = 0; i < input_len; i++) */
    /*     printf("%02x ", input[i]); */
    /* printf("\n"); */

    // Add null terminator and print decrypted text
    (*output)[decryptedtext_len] = '\0';
    /* printf("Decrypted Text: "); */
    /* for (int i = 0; i < decryptedtext_len; i++) */
    /*     printf("%02x ", (*output)[i]); */
    /* printf("\n"); */

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}

/**
 *
 */
int
evaluate_polynomial_at(
    BIGNUM   **share,
    BIGNUM *coeffs[],
    int        input,
    int    threshold,
    BIGNUM  *modulus)
{
    int r;
    BIGNUM *x;
    BN_CTX *ctx = BN_CTX_new();
    x = BN_new();
    r = BN_set_word(x, (unsigned long)input);
    if (!r) { return openssl_error("Failed to initialize input x"); }
    *share = BN_dup(coeffs[threshold-1]);
    if (!(*share)) { return openssl_error("Failed to alloc share"); }
    /* Stop before 0 so prevent undef behav */
    for (int i = threshold - 1; i > 0; i--) {
	r = BN_mod_mul(*share, *share, x, modulus, ctx);
	if (!r) {return openssl_error("Failed share * x"); }
	r = BN_mod_add(*share, *share, coeffs[i - 1], modulus, ctx);
	if (!r) {return openssl_error("Failed share + coeffs[i - 1]"); }
    }
    BN_free(x);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 * Generates 'n'='num_shares' shares of 'secret' using a (t, n)-SSS Scheme ('t'='threshold').
 * Shares are created as poly(1..n+1)
 * @param Output array to hold shares
 * @param Secret to share
 * @param threshold
 * @param number of shares
 * @param group order
 */
int
construct_shamir_shares (
    BIGNUM **shares,
    BIGNUM  *secret,
    BIGNUM *modulus,
    InputArgs    ia)
{
    int r;
    BIGNUM *coeffs[ia.threshold];
    BN_CTX *ctx = BN_CTX_new();

    coeffs[0] = BN_dup(secret);
    for (int i = 1; i < ia.threshold; i++) {
	coeffs[i] = BN_new();
	if (!coeffs[i]) { return openssl_error("Failed to alloc coeffs"); }
	r = BN_rand_range_ex(coeffs[i], modulus, ia.secpar, ctx);
	if (!r) { return openssl_error("Failed to gen random coefficients"); }
    }
    for (int i = 0; i < ia.num_entries; i++) {
	/* Fn alloc's shares[i] */
	r = evaluate_polynomial_at(&shares[i], coeffs, i + 1, ia.threshold, modulus);
	if (!r) { return general_error("Failed evaluate_polynomial_at i+1"); }
    }

    BN_CTX_free(ctx);
    return SUCCESS;
}

int
try_reconstruct_with (
    BIGNUM **secret,
    BIGNUM      **x,
    BIGNUM      **y,
    int      length,
    BIGNUM *modulus)
{
    int r;
    BIGNUM *sum_accum;
    BIGNUM *mul_accum;
    BIGNUM *tmp;
    BN_CTX *ctx = BN_CTX_new();
    sum_accum = BN_new();
    mul_accum = BN_new();
    tmp = BN_new();
    BN_zero(sum_accum);
    for (int i = 0; i < length; i++) {
	BN_one(mul_accum);
	for (int j = 0; j < length; j++) {
	    if (i == j) {
		continue;
	    }
	    r = BN_mod_sub(tmp, x[j], x[i], modulus, ctx);
	    BN_mod_inverse(tmp, tmp, modulus, ctx);
	    r = BN_mod_mul(tmp, x[j], tmp, modulus, ctx);
	    r = BN_mod_mul(mul_accum, mul_accum, tmp, modulus, ctx);
	}
	r = BN_mod_mul(mul_accum, y[i], mul_accum, modulus, ctx);
	r = BN_mod_add(sum_accum, sum_accum, mul_accum, modulus, ctx);
    }
    if (!r) { return openssl_error("An error occurred be more specific"); }
    (*secret) = BN_dup(sum_accum);
    if (!(*secret)) { return openssl_error("Failed to dup sum_accum"); }

    BN_free(sum_accum);
    BN_free(mul_accum);
    BN_free(tmp);
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 * @param
 * @param the attempted reconstructed secret
 * @param the shares given
 * @param the threshold
 * @param the number of shares
 * @param an array containing the indexes of the nCt combination of shares we are trying
 * @param the field order
 */
int
reconstruct_shamir_secret (
    BIGNUM         **secret,
    BIGNUM         **shares,
    size_t        threshold,
    size_t subset_indexes[],
    BIGNUM         *modulus)
{
    int r;
    size_t t = threshold;
    size_t i;
    BIGNUM *save_x[threshold];
    BIGNUM *save_y[threshold];
    BN_CTX *ctx = BN_CTX_new();

    for (i = 0; i < t; i++) {
	save_x[i] = BN_new();
	save_y[i] = BN_new();
	BN_set_word(save_x[i], subset_indexes[i] + 1);
	BN_copy(save_y[i], shares[subset_indexes[i]]);
    }
    /* for (i = 0; i < t; i++) { */
    /* 	printf("x = "); BN_print_fp(stdout, save_x[i]); */
    /* 	printf(", y = "); BN_print_fp(stdout, save_y[i]); printf("\n"); */
    /* } */
    /* Fn alloc's secret */
    r = try_reconstruct_with(secret, save_x, save_y, t, modulus);
    if (!r) { return openssl_error("Failed during try_reconstruct_with"); }
    for (i = 0; i < t; i++) {
	BN_free(save_x[i]);
	BN_free(save_y[i]);
    }
    BN_CTX_free(ctx);
    return SUCCESS;
}

/**
 *
 */
int
iteratively_check_all_subsets (
    unsigned char *secret_digest,
    BIGNUM             *shares[],
    InputArgs                 ia,
    BIGNUM              *modulus)
{
    int r;
    const size_t n = ia.num_entries;
    const size_t t = ia.threshold;
    /* Array to store indices of selected elements */
    size_t subset_indexes[t];

    /* Initialize the first subset as [0, 1, 2, ..., t-1] */
    for (size_t i = 0; i < t; i++) {
        subset_indexes[i] = i;
    }

    /* START: Check the current subset for validity */
    BIGNUM *possible_secret;
    unsigned char *possible_secret_digest;
    size_t digest_len;
    while (subset_indexes[0] < n - t + 1) {

	for (size_t i = 0; i < t; i++) {
	    printf((i == t-1 ? "%zu:\n" : "%zu, "), subset_indexes[i]);
	}	
	/* Fn alloc's possible_secret */
	r = reconstruct_shamir_secret(&possible_secret, shares, ia.threshold,
				      subset_indexes, modulus);
	if (!r) { return general_error("Failed to reconstruct shamir secret"); }
	switch (ia.secpar) {
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's possible_secret_digest */
	    r = hash(&possible_secret_digest, possible_secret, "SHA1", digest_len, Bignum);
	    break;
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&possible_secret_digest, possible_secret, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash poissble_secret"); }
	printf("------------------\n");
	for (size_t j = 0; j < digest_len; j++)
	    printf("%02x ", secret_digest[j]);
	printf("\n");
	for (size_t j = 0; j < digest_len; j++)
	    printf("%02x ", possible_secret_digest[j]);
	printf("\n\n\n");
	if (0 == memcmp(secret_digest, possible_secret_digest, digest_len)) {
	    printf("SUCCESS :)\n");
	    BN_free(possible_secret);
	    free(possible_secret_digest);	    
	    return SUCCESS;
	}
	BN_free(possible_secret);
	free(possible_secret_digest);
	/* END: Check the current subset viability */

        /* Generate the next subset */
        ssize_t i = t - 1;
        while (i >= 0 && subset_indexes[i] == i + n - t) {
            i--;
        }

	/* All subsets generated */	
        if (i < 0) {
	    printf("FAILURE :(\n");
	    printf("Threshold unmet\n");	    	    
            break;
        }

        subset_indexes[i]++;

        /* Update the rest of the indices */
        for (size_t j = i + 1; j < t; j++) {
            subset_indexes[j] = subset_indexes[j - 1] + 1;
        }
    }
    return SUCCESS;
}
