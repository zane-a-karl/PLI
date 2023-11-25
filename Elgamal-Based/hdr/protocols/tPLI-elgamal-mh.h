#ifndef T_PLI_ELGAMAL_MH_H
#define T_PLI_ELGAMAL_MH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include <netdb.h>                      // struct sockaddr
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

int
server_run_t_pli_elgamal_mh (
    int   new_fd,
    InputArgs ia);

int
client_run_t_pli_elgamal_mh (
    int   sockfd,
    InputArgs ia);

#endif//T_PLI_ELGAMAL_MH_H
