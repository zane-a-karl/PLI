#ifndef PLI_ELGAMAL_AH_H
#define PLI_ELGAMAL_AH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

int
server_run_pli_elgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_elgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//PLI_ELGAMAL_AH_H
