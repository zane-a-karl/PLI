#ifndef ECELGAMAL_THRESHOLDING_H
#define ECELGAMAL_THRESHOLDING_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/ec.h>                 // EC_GROUP
#include "../../hdr/ecelgamal/utils.h"  // EcGamalKeys
#include "../../hdr/input-args/utils.h" // InputArgs
#include <netdb.h>                      // struct sockaddr
#include "../../hdr/macros.h"           // SUCCESS
**********************************************************/

int
ecelgamal_server_thresholding(
    size_t            *matches,
    int                     fd,
    EcGamalKeys    server_keys,
    EcGamalCiphertext cipher[],
    InputArgs               ia);

int
ecelgamal_client_thresholding (
    int                     fd,
    EcGamalPk        server_pk,
    EcGamalCiphertext cipher[],
    InputArgs               ia);

#endif//ECELGAMAL_THRESHOLDING_H
