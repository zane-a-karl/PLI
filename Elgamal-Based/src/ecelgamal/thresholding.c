#include "../../hdr/ecelgamal/thresholding.h"


/**
 * Completes the following steps:
 *  1. Recv XOR enryptions of shares
 *  2. Recv hash(s)
 *  3. Decrypt XOR encryptions using hash(client_cipher[i].c1^sk) as keys
 *  4. Reconstruct SSS's using output from (3) to get potential secret
 *  5. hash(output of (4)) and compare with hash(s) from (2)
 */
int
ecelgamal_server_thresholding (
    size_t            *matches,
    int                     fd,
    EcGamalKeys    server_keys,
    EcGamalCiphertext cipher[],
    InputArgs               ia)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    /* 1. recv the XOR encrytions */
    unsigned char *sym_enc_shares[ia.num_entries];
    size_t sym_enc_shares_lens[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	r = recv_msg(fd, &sym_enc_shares_lens[i], "Server recv sym_enc_shares_lens[i]:", SizeT);
	if (r == -1) { return general_error("Failed to recv xor cipher lens"); }
	sym_enc_shares[i] = calloc(sym_enc_shares_lens[i], sizeof(unsigned char));
	r = recv_msg(fd, &sym_enc_shares[i], "Server recv sym_enc_shares:",
		     UnsignedChar, sym_enc_shares_lens[i]);
	if (r == -1) { return general_error("Failed to recv xor cipher"); }
    }

    /* 2. recv hash(s) */
    unsigned char *secret_digest = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
    r = recv_msg(fd, &secret_digest, "Server recv secret digest:",
		 UnsignedChar, EVP_MAX_MD_SIZE);
    if (r == -1) { return general_error("Failed to recv secret digest"); }

    /* 3. decrypt the AES encryptions to get s'_i  */
    unsigned char *cipher_digests[ia.num_entries];
    size_t digest_len;
    unsigned char *uchar_shares[ia.num_entries];
    BIGNUM *shares[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* BIG NOTE: I've stored cipher[i].c1 * sk into cipher[i].c2, this is bad, but
	   easier to code, because now I don't need to initialize another BIGNUM */
	r = EC_POINT_mul(server_keys.pk->group, cipher[i].c2, NULL,
			 cipher[i].c1, server_keys.sk->secret, ctx);
	if (!r) { return openssl_error("Failed to ptmul cipher.c1 * sk"); }

	switch (ia.secpar) {
	case 160:		/* Fall through */
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's cipher_digests[i] */
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA1", digest_len, Ecpoint,
		     server_keys.pk->group);
	    break;
	case 224:		/* Fall through */
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA224", digest_len, Ecpoint,
		     server_keys.pk->group);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA256", digest_len, Ecpoint,
		     server_keys.pk->group);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash cipher[i].c1^sk"); }
	uchar_shares[i] = calloc(sym_enc_shares_lens[i], sizeof(unsigned char));
	for (int j = 0; j < sym_enc_shares_lens[i]; j++) {
	    if (j < digest_len) {
		uchar_shares[i][j] = sym_enc_shares[i][j] ^ cipher_digests[i][j % digest_len];
	    } else {
		uchar_shares[i][j] = sym_enc_shares[i][j];
	    }
	}
	/* printf("Decrypted Shares: "); */
	/* for (int j = 0; j < sym_enc_shares_lens[i]; j++) */
	/*     printf("%02x ", uchar_shares[i][j]); */
	/* printf("\n"); */
	shares[i] = BN_new();
	BN_bin2bn(uchar_shares[i], sym_enc_shares_lens[i], shares[i]);
	if (!shares[i]) { return openssl_error("Failed to bin2bn the uchar shares"); }
    }
    /* for (size_t i = 0; i < ia.num_entries; i++) { */
    /* 	printf("Keys(cipher digests) ------>: "); */
    /* 	for (int j = 0; j < digest_len; j++) */
    /* 	    printf("%02x ", cipher_digests[i][j]); */
    /* 	printf("\n"); */
    /* } */

    /* 4. reconstruct SSS's with the s'_i's to get s' */
    /* 5. hash s' and compare with the hash(s) you received */
    for (size_t i = 0; i < ia.num_entries; i++) {
	matches[i] = 0;
    }
    /* r = iteratively_check_all_subsets(matches, secret_digest, shares, ia, server_keys.pk->p); */
    /* if (!r) { return general_error("Failed during iteratively_check_all_subsets"); } */
    r = exec_BW_alg(matches, secret_digest, shares, ia, server_keys.pk->p);
    if (!r) { return general_error("Failed during exec_BW_alg"); }

    for (size_t i = 0; i < ia.num_entries; i++) {
	free(sym_enc_shares[i]);
	free(uchar_shares[i]);
    }
    free(secret_digest);
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 * Completes the following steps:
 *  1. generate a random secret value 's'
 *  2. secret share 's' using SSS to generate 'n' shares (s_i)
 *  3. hash (exp_res[i].c2) and store into exp_res_hashes[i]
 *  4. Encrypt (s_i) with AES using arr[i] as key
 *  5. send iv's, output of (4), and hash(s) to server
 */
int
ecelgamal_client_thresholding (
    int                     fd,
    EcGamalPk        server_pk,
    EcGamalCiphertext cipher[],
    InputArgs               ia)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    /* 1. generate a random secret value 's' */
    BIGNUM *bn_secret;
    bn_secret = BN_new();
    r = BN_rand_range_ex(bn_secret, server_pk.p, ia.secpar, ctx);
    if (!r) { return openssl_error("Failed to gen bn_secret"); }

    /* 2. secret share 's' using SSS to generate 'n' shares (s_i) */
    BIGNUM *shares[ia.num_entries];
    /* Fn alloc's ia.num_entries shares */
    r = construct_shamir_shares(shares, bn_secret, server_pk.p, ia);
    if (!r) { return general_error("Failed to construct shamir shares"); }
    unsigned char *uchar_shares[ia.num_entries];
    for (size_t i = 0; i < ia.num_entries; i++) {
	/* printf("Uchar Shares: "); */
	uchar_shares[i] = calloc(BN_num_bytes(shares[i]), sizeof(unsigned char));
	BN_bn2bin(shares[i], uchar_shares[i]);
	if (!(uchar_shares + i)) { return openssl_error("Failed to bn2bin the shares"); }
	/* for (int j = 0; j < BN_num_bytes(shares[i]); j++) */
	/*     printf("%02x ", uchar_shares[i][j]); */
	/* printf("\n"); */
    }

    /* 3. hash (cipher[i].c2) and store into cipher_hashes[i] */
    unsigned char *cipher_digests[ia.num_entries];
    unsigned char *secret_digest;
    size_t digest_len;
    for (size_t i = 0; i < ia.num_entries; i++) {
	switch (ia.secpar) {
	case 160:		/* Fall through */
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's cipher_digests[i] */
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA1", digest_len, Ecpoint,
		     server_pk.group);
	    r &= hash(&secret_digest, bn_secret, "SHA1", digest_len, Bignum);
	    break;
	case 224:		/* Fall through */
	case 2048:
	    digest_len = SHA224_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA224", digest_len, Ecpoint,
		     server_pk.group);
	    r &= hash(&secret_digest, bn_secret, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA256", digest_len, Ecpoint,
		     server_pk.group);
	    r &= hash(&secret_digest, bn_secret, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash cipher[i].c2 or secret"); }
	/* printf("Keys(cipher digests) ------>: "); */
	/* for (int j = 0; j < digest_len; j++) */
	/*     printf("%02x ", cipher_digests[i][j]); */
	/* printf("\n"); */
    }
    /* printf("##########################################################\n"); */
    /* printf("digest len = %zu\n", digest_len); */
    /* printf("##########################################################\n"); */

    /* 4. Encrypt (s_i) with AES using arr[i] as key */
    unsigned char *sym_enc_shares[ia.num_entries];
    size_t sym_enc_shares_lens[ia.num_entries];
    size_t bytes_per_share;
    for (size_t i = 0; i < ia.num_entries; i++) {
	bytes_per_share = BN_num_bytes(shares[i]);
	sym_enc_shares[i] = calloc(bytes_per_share, sizeof(unsigned char));
	for (int j = 0; j < bytes_per_share; j++) {
	    if (j < digest_len) {
		sym_enc_shares[i][j] = cipher_digests[i][j % digest_len] ^ uchar_shares[i][j];
	    } else {
		sym_enc_shares[i][j] = uchar_shares[i][j];
	    }
	}
	sym_enc_shares_lens[i] = bytes_per_share;
	/* printf("Encrypted Shares: "); */
	/* for (int j = 0; j < sym_enc_shares_lens[i]; j++) */
	/*     printf("%02x ", sym_enc_shares[i][j]); */
	/* printf("\n"); */
    }

    /* 5. send output of (4), and hash(s) to server */
    for (size_t i = 0; i < ia.num_entries; i++) {
	r = send_msg(fd, &sym_enc_shares_lens[i], "Client sent cipher share len:", SizeT);
	if (!r) { return general_error("Failed to send sym_enc_shares_lens[i]"); }
	r = send_msg(fd, sym_enc_shares[i], "Client sent cipher share:", UnsignedChar,
		     sym_enc_shares_lens[i]);
	if (!r) { return general_error("Failed to send ciphertext_shares[i]"); }
    }
    /* printf("more bytes for full message = %lu\n", sym_enc_shares_lens[0]); */
    /* printf("more bytes for full message = %lu\n", digest_len); */
    /* printf("\n\nsecret digest length is %zu\n\n", digest_len); */
    r = send_msg(fd, secret_digest, "Client sent secret digest:", UnsignedChar, digest_len);
    if (!r) { return general_error("Failed to send secret digest"); }

    for (size_t i = 0; i < ia.num_entries; i++) {
	free(uchar_shares[i]);
	free(sym_enc_shares[i]);
    }
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
