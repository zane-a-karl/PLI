#ifndef _T_PLI_ELGAMAL_MH_H_
#define _T_PLI_ELGAMAL_MH_H_

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "../logging-utils.h"
#include "../elgamal/mh-utils.h"
#include "../elgamal/thresholding.h"

typedef struct InputArgs InputArgs;

int
server_run_t_pli_elgamal_mh (
    int   new_fd,
    InputArgs ia);

int
client_run_t_pli_elgamal_mh (
    int   sockfd,
    InputArgs ia);

#endif//_T_PLI_ELGAMAL_MH_H_
