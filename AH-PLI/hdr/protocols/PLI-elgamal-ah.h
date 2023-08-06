#ifndef _PLI_ELGAMAL_AH_H_
#define _PLI_ELGAMAL_AH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../elgamal/ah-utils.h"

int
permute_elgamal_ciphertexts (
    GamalCiphertext **ctxts,
    unsigned long       len);

int
server_run_pli_elgamal_ah (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_pli_elgamal_ah (
    int                  sockfd,
    int                 sec_par,
    char              *filename);

#endif//_PLI_ELGAMAL_AH_H_
