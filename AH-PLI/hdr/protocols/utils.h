#ifndef _PROTOCOLS_UTILS_H_
#define _PROTOCOLS_UTILS_H_

#include "PLI-elgamal-ah.h"
#include "PLI-elgamal-mh.h"
#include "PLI-ecelgamal-ah.h"
/* #include "PLI-ecelgamal-mh.h" */

#include "PLIca-elgamal-ah.h"
#include "PLIca-elgamal-mh.h"
#include "PLIca-ecelgamal-ah.h"
/* #include "PLIca-ecelgamal-mh.h" */

#include "tPLI-elgamal-ah.h"
#include "tPLI-elgamal-mh.h"
#include "tPLI-ecelgamal-ah.h"
/* #include "tPLI-ecelgamal-mh.h" */

#include "tPLIca-elgamal-ah.h"
#include "tPLIca-elgamal-mh.h"
#include "tPLIca-ecelgamal-ah.h"
/* #include "tPLI-ecelgamal-mh.h" */

typedef int (*PliProtocol)(int, InputArgs);

extern
PliProtocol callback[NUM_PARTY_TYPES][NUM_PLI_METHODS][NUM_ELGAMAL_FLAVORS][NUM_HOMOMORPHISM_TYPES];

int
run (
    PliProtocol pp,
    int         fd,
    InputArgs   ia);

#endif//_PROTOCOLS_UTILS_H_
