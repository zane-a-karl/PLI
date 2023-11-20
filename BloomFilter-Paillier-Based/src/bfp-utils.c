#include "../hdr/bfp-utils.h"


int
get_murmur2hash_indexes (
    unsigned long *entry_indexes,
    void *                buffer,
    unsigned long            len,
    bloom_filter_t           *bf)
{
    /* Magic number copied from bloom_check_add() */
    unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
    if (!a) { return general_error("Failed to murmur2hash magic number"); }
    unsigned int b = murmurhash2(buffer, len, a);
    if (!b) { return general_error("Failed to murmur2hash buffer"); }
    unsigned long x;

    for (unsigned long i = 0; i < bf->hashes; i++) {
	x = (a + b*i) % bf->bits;
	entry_indexes[i] = x >> 3;
    }
    return SUCCESS;
}
