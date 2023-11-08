#ifndef _PLI_ECELGAMAL_AH_H_
#define _PLI_ECELGAMAL_AH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../ecelgamal/ah-utils.h"

typedef struct InputArgs InputArgs;

int
server_run_pli_ecelgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_ecelgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//_PLI_ECELGAMAL_AH_H_
