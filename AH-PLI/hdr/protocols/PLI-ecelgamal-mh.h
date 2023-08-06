#ifndef _PLI_ECELGAMAL_MH_H_
#define _PLI_ECELGAMAL_MH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../ecelgamal/mh-utils.h"


int
server_run_pli_ecelgamal_mh (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_pli_ecelgamal_mh (
    int                  sockfd,
    int                 sec_par,
    char *             filename);

#endif//_PLI_ECELGAMAL_MH_H_
