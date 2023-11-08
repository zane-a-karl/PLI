#ifndef _PLI_ECELGAMAL_MH_H_
#define _PLI_ECELGAMAL_MH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../ecelgamal/mh-utils.h"

typedef struct InputArgs InputArgs;

int
server_run_pli_ecelgamal_mh (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_ecelgamal_mh (
    int   sockfd,
    InputArgs ia);

#endif//_PLI_ECELGAMAL_MH_H_
