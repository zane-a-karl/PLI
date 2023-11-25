#ifndef ELEGAMAL_THRESHOLDING_H
#define ELEGAMAL_THRESHOLDING_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/elgamal/utils.h"    // GamalKeys
#include "../../hdr/input-args/utils.h" // struct InputArgs
#include <netdb.h>                      // struct sockaddr
#include <openssl/ec.h>                 // EC_POINT
#include "../../hdr/macros.h"           // SUCCESS
**********************************************************/

int
elgamal_server_thresholding(
    size_t          *matches,
    int                   fd,
    GamalKeys    server_keys,
    GamalCiphertext cipher[],
    InputArgs             ia);

int
elgamal_client_thresholding (
    int                   fd,
    GamalPk        server_pk,
    GamalCiphertext cipher[],
    InputArgs             ia);

#endif//ELEGAMAL_THRESHOLDING_H
