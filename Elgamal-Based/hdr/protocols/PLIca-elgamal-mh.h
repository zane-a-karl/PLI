#ifndef PLI_CA_ELGAMAL_MH_H
#define PLI_CA_ELGAMAL_MH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

int
server_run_pli_ca_elgamal_mh (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_ca_elgamal_mh (
    int   sockfd,
    InputArgs ia);

#endif//PLI_CA_ELGAMAL_MH_H
