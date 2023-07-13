#include "../hdr/elgamal-mh.h"


int
mh_elgamal_encrypt (GamalCiphertext *cipher,
		    GamalPk              pk,
		    BIGNUM    *bn_plaintext)
{
    int r = 1;
    BIGNUM *bn_rand_elem;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { r = 0; perror("Failed to create new ctx"); return FAILURE; }
    bn_rand_elem = BN_new();
    if (!bn_rand_elem) { r = 0; perror("Failed to make new bn"); return FAILURE; }
    cipher->c1 = BN_new();
    if (!cipher->c1) { r = 0; perror("Failed to make new bn"); return FAILURE;  }
    cipher->c2 = BN_new();
    if (!cipher->c2) { r = 0; perror("Failed to make new bn"); return FAILURE; }
    printf("###############3\n");    
    printf("r = %i\n", r);
    printf("###############3\n");    
    r &= BN_rand_range_ex(bn_rand_elem, pk.modulus, SEC_PAR, ctx);
    if (!r) { perror("Failed to gen rand elem"); return FAILURE; }

    // Set c1 = generator^rand_elem
    r &= BN_mod_exp(cipher->c1, pk.generator, bn_rand_elem, pk.modulus, ctx);
    if (!r) { perror("Failed to calc g^rand_elem"); return FAILURE; }
    // Set c2 = m * mul_mask^rand_elem
    r &= BN_mod_exp(cipher->c2, pk.mul_mask, bn_rand_elem, pk.modulus, ctx);
    if (!r) { perror("Failed to calc h^rand_elem"); return FAILURE; }
    r &= BN_mod_mul(cipher->c2, bn_plaintext, cipher->c2, pk.modulus, ctx);
    if (!r) { perror("Failed to calc ptxt * h^rand"); return FAILURE; }

    BN_free(bn_rand_elem);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

int
mh_elgamal_decrypt (BIGNUM    *bn_plaintext,
		    GamalKeys          keys,
		    GamalCiphertext  cipher)
{
    int r = 1;
    BIGNUM *denominator;
    BIGNUM *tmp;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {r = 0; perror("Failed to create new ctx"); return FAILURE; }
    denominator = BN_new();
    if (!denominator) { r = 0; perror("Failed to make new bn"); return FAILURE; }

    // Calculate 1/c1 then 1/c1^sk
    tmp = BN_mod_inverse(denominator, cipher.c1, keys.pk->modulus, ctx);  
    if (!tmp) { r = 0; perror("Failed to calc 1/c1"); return FAILURE; }
    r &= BN_mod_exp(denominator, denominator, keys.sk->secret, keys.pk->modulus, ctx);
    if (!r) { perror("Failed to calc (1/c1)^sk"); return FAILURE; }
    // Evaluate c2/c1^sk
    r &= BN_mod_mul(bn_plaintext, cipher.c2, denominator, keys.pk->modulus, ctx);
    if (!r) { perror("Failed to calc c2/c1^sk"); return FAILURE; }

    BN_free(denominator);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
