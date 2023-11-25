#ifndef PLI_ECELGAMAL_AH_H
#define PLI_ECELGAMAL_AH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
#include "../../hdr/input-args/utils.h" // InputArgs
**********************************************************/

int
server_run_pli_ecelgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_ecelgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//PLI_ECELGAMAL_AH_H
