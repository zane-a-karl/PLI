#ifndef PLI_CA_ECELGAMAL_AH_H
#define PLI_CA_ECELGAMAL_AH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

int
server_run_pli_ca_ecelgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_pli_ca_ecelgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//PLI_CA_ECELGAMAL_AH_H
