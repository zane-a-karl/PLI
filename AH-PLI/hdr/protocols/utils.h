#ifndef _PROTOCOLS_UTILS_H_
#define _PROTOCOLS_UTILS_H_

#include <ctype.h>

#include "PLI-elgamal-ah.h"
#include "PLI-elgamal-mh.h"
#include "PLI-ecelgamal-ah.h"
#include "PLI-ecelgamal-mh.h"

#include "PLIca-elgamal-ah.h"
#include "PLIca-elgamal-mh.h"
#include "PLIca-ecelgamal-ah.h"


enum PliMethod {
    PLI,			/* 0 */
    PLI_ca,			/* 1 */
    t_PLI,			/* 2 */
    PLI_x,			/* 3 */
    t_PLI_ca,			/* 4 */
    t_PLI_x,			/* 5 */
    NUM_PLI_METHODS
};

/* EG = regular Elgamal,
   ECEG = Elliptic Curve Elgamal */
enum ElgamalFlavor {
    EG,				/* 0 */
    ECEG,			/* 1 */
    NUM_ELGAMAL_FLAVORS
};

/* AH = additively homomorphic,
   MH = multiplicatively homomorphic */
enum HomomorphismType {
    AH,				/* 0 */
    MH,				/* 1 */
    NUM_HOMOMORPHISM_TYPES
};


typedef int (*PliProtocol)(int, int, char *);

extern
PliProtocol callback[NUM_PARTY_TYPES][NUM_PLI_METHODS][NUM_ELGAMAL_FLAVORS][NUM_HOMOMORPHISM_TYPES];

int
run (
    PliProtocol pp,
    int         fd,
    int    sec_par,
    char *filename);

int
str_to_pli_method (
    enum PliMethod *pm,
    char          *str);

int
str_to_homomorphism_type (
    enum HomomorphismType *ht, 
    char                 *str);

int
str_to_elgamal_flavor (
    enum ElgamalFlavor *ef, 
    char              *str);
int
str_to_int (
    int *output,
    char *input);

#endif//_PROTOCOLS_UTILS_H_
