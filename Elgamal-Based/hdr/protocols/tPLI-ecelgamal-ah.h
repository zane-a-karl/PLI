#ifndef _T_PLI_ECELGAMAL_AH_H_
#define _T_PLI_ECELGAMAL_AH_H_

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "../logging-utils.h"
#include "../ecelgamal/ah-utils.h"
#include "../ecelgamal/thresholding.h"

typedef struct InputArgs InputArgs;

int
server_run_t_pli_ecelgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_t_pli_ecelgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//_T_PLI_ECELGAMAL_AH_H_
