#ifndef _T_PLI_ELGAMAL_MH_H_
#define _T_PLI_ELGAMAL_MH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../elgamal/mh-utils.h"

int
server_run_t_pli_elgamal_mh (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_t_pli_elgamal_mh (
    int                  sockfd,
    int                 sec_par,
    char *             filename);

#endif//_T_PLI_ELGAMAL_MH_H_
