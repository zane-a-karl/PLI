#ifndef PROTOCOLS_UTILS_H
#define PROTOCOLS_UTILS_H

/*******************Include Prerequisites******************
#include <stdlib.h>                     // size_t
#include <openssl/bn.h>                 // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
**********************************************************/

typedef int (*PliProtocol)(int, InputArgs);

extern
PliProtocol callback[NUM_PARTY_TYPES][NUM_PLI_METHODS][NUM_ELGAMAL_FLAVORS][NUM_HOMOMORPHISM_TYPES];

int
run (
    PliProtocol pp,
    int         fd,
    InputArgs   ia);

#endif//PROTOCOLS_UTILS_H
