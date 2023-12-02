#ifndef INPUT_ARGS_UTILS
#define INPUT_ARGS_UTILS

/*******************Include Prerequisites******************
#include <stdlib.h>           // size_t
#include <openssl/bn.h>       // BIGNUM
#include "../../hdr/macros.h" // SUCCESS
**********************************************************/

enum PartyType {
    CLIENT,
    SERVER,
    NUM_PARTY_TYPES
};

enum MessageType {
    Integer,
    SizeT,
    UnsignedChar,
    Bignum,
    Ecpoint,
    NUM_MESSAGE_TYPES
};

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

typedef struct InputArgs {
    char              *hostname;
    enum PliMethod        pmeth;
    enum ElgamalFlavor    eflav;
    enum HomomorphismType htype;
    size_t               secpar;
    size_t          num_entries;
    size_t            threshold;
    size_t     expected_matches;
    char       *client_filename;
    char       *server_filename;
} InputArgs;

int
parse_input_args (
    InputArgs        *ia,
    int             argc,
    char          **argv,
    enum PartyType party);

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
str_to_size_t (
    size_t *output,
    char    *input);

int
parse_file_for_num_entries (
    size_t *num_entries,
    char      *filename);

int
parse_file_for_list_entries (
    BIGNUM **entries,
    int  num_entries,
    char   *filename);

#endif//INPUT_ARGS_UTILS
