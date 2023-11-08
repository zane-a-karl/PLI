#ifndef _T_PLI_CA_ELGAMAL_AH_H_
#define _T_PLI_CA_ELGAMAL_AH_H_

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "../logging-utils.h"
#include "../elgamal/ah-utils.h"
#include "../elgamal/thresholding.h"

typedef struct InputArgs InputArgs;

int
server_run_t_pli_ca_elgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_t_pli_ca_elgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//_T_PLI_CA_ELGAMAL_AH_H_
