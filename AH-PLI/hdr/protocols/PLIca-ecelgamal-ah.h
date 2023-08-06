#ifndef _PLI_CA_ECELGAMAL_AH_H_
#define _PLI_CA_ECELGAMAL_AH_H_

#include <openssl/rand.h>
#include "../logging-utils.h"
#include "../ecelgamal/ah-utils.h"


int
server_run_pli_ca_ecelgamal_ah (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_pli_ca_ecelgamal_ah (
    int                  sockfd,
    int                 sec_par,
    char              *filename);

#endif//_PLI_CA_ECELGAMAL_AH_H_
