#ifndef _BFP_UTILS_H_
#define _BFP_UTILS_H_

#include "../hdr/utils.h"
#include "../hdr/murmurhash2.h"

typedef struct paillier_keys_t {
    paillier_pubkey_t *pk;
    paillier_prvkey_t *sk;
} paillier_keys_t;

typedef struct bloom bloom_filter_t;

int
get_murmur2hash_indexes (
    unsigned long *entry_indexes,
    void *                buffer,
    unsigned long            len,
    bloom_filter_t           *bf);

#endif//_BFP_UTILS_H_
