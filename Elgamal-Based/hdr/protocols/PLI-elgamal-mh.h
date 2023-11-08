#ifndef _PLI_ELGAMAL_MH_H_
#define _PLI_ELGAMAL_MH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../elgamal/mh-utils.h"

typedef struct InputArgs InputArgs;

int
server_run_pli_elgamal_mh (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_elgamal_mh (
    int   sockfd,
    InputArgs ia);

#endif//_PLI_ELGAMAL_MH_H_
