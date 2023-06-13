#include "ah-ecelgamal.h"

#define SUCCESS 0
#define FAILURE 1

/**
 * Encrypts g^m where g is the generator and m the message
 * @param ciphertext output
 * @param plaintext input
 * @param encryption key input
 * @param curve group
 * @return SUCCESS/FAILURE
 */
int
ah_gamal_encrypt (ah_gamal_ciphertext *ctxt,
		  uint64_t *plaintext,
		  ah_gamal_key *key,
		  EC_GROUP *ec_group)
{
    BIGNUM *bn_plaintext, *bn_order, *bn_rand_num;
    BN_CTX *ctx = BN_CTX_new();

    bn_plaintext = BN_new();
    bn_order = BN_new();
    bn_rand_num = BN_new();
    ciphertext->C2 = EC_POINT_new(ec_group);

    EC_GROUP_get_order(ec_group, bn_order, ctx);
    BN_rand_range(bn_rand_num, bn_order);

    BN_set_word(bn_plaintext, plaintext);

    ciphertext->C1 = 
}