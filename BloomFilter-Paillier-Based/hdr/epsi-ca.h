#ifndef _EPSI_CA_H_
#define _EPSI_CA_H_

#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <sys/wait.h>   // wait()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep(), fork()
#include "../hdr/utils.h"
#include "../hdr/bfp-utils.h"


int
server_run_epsi_ca (
    int                          new_fd,
    int                     num_entries,
    paillier_plaintext_t **list_entries,
    paillier_keys_t         server_keys,
    paillier_pubkey_t         client_pk);

int
client_run_epsi_ca (
    int                          sockfd,
    int                     num_entries,
    paillier_plaintext_t **list_entries,
    paillier_keys_t         client_keys,
    paillier_pubkey_t         server_pk);

#endif//_EPSI_CA_H_
