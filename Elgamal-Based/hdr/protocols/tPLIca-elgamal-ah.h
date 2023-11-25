#ifndef T_PLI_CA_ELGAMAL_AH_H
#define T_PLI_CA_ELGAMAL_AH_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include <netdb.h>                      // struct sockaddr
#include "../../hdr/elgamal/utils.h"    // GamalCiphertext
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

int
server_run_t_pli_ca_elgamal_ah (
    int   new_fd,
    InputArgs ia);

int
client_run_t_pli_ca_elgamal_ah (
    int   sockfd,
    InputArgs ia);

#endif//T_PLI_CA_ELGAMAL_AH_H
