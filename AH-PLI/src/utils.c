#include "../hdr/utils.h"

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
