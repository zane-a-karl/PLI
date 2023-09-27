#include "../../hdr/elgamal/thresholding.h"

/**
 * Completes the following steps:
 *  1. Recv XOR enryptions of shares
 *  2. Recv hash(s)
 *  3. Decrypt XOR encryptions using hash(client_cipher[i].c1^sk) as keys
 *  4. Reconstruct SSS's using output from (3) to get potential secret
 *  5. hash(output of (4)) and compare with hash(s) from (2)
 */
int
elgamal_server_brute_force_thresholding (
    int                   fd,
    GamalKeys    server_keys,
    GamalCiphertext cipher[],
    InputArgs             ia,
    int          num_entries)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    /* 1. recv the XOR encrytions */
    unsigned char *sym_enc_shares[num_entries];
    size_t sym_enc_shares_lens[num_entries];
    for (int i = 0; i < num_entries; i++) {
	r = recv_msg(fd, &sym_enc_shares_lens[i], "Server recv sym_enc_shares_lens[i]:", SizeT);
	if (!r) { return general_error("Failed to recv xor cipher lens"); }
	sym_enc_shares[i] = calloc(sym_enc_shares_lens[i], sizeof(unsigned char));
	r = recv_msg(fd, &sym_enc_shares[i], "Server recv sym_enc_shares:",
		     UnsignedChar, sym_enc_shares_lens[i]);
	if (!r) { return general_error("Failed to recv xor cipher"); }
    }

    /* 2. recv hash(s) */
    unsigned char *secret_digest = calloc(MAX_MSG_LEN, sizeof(unsigned char));
    r = recv_msg(fd, &secret_digest, "Server recv secret digest:",
		 UnsignedChar, EVP_MAX_MD_SIZE);
    if (!r) { return general_error("Failed to recv secret digest"); }

    /* 3. decrypt the AES encryptions to get s'_i  */
    unsigned char *cipher_digests[num_entries];
    unsigned char *key;
    size_t digest_len;
    unsigned char *uchar_shares[num_entries];
    BIGNUM *shares[num_entries];
    for (int i = 0; i < num_entries; i++) {
	/* BIG NOTE: I've stored cipher[i].c1^sk into cipher[i].c2,
	   this is bad, but easier to code, because now I don't
	   need to initialize another BIGNUM */
	r = BN_mod_exp(cipher[i].c2, cipher[i].c1, server_keys.sk->secret,
		       server_keys.pk->modulus, ctx);
	if (!r) { return openssl_error("Failed to mod exp cipher.c1^sk"); }

	switch (ia.secpar) {
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's cipher_digests[i] */
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA1", digest_len, Bignum);
	    break;
	case 2048:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash cipher[i].c1^sk"); }
	key = cipher_digests[i];
	/* printf("Keys ------>: "); */
	/* for (int j = 0; j < digest_len; j++) */
	/*     printf("%02x ", key[j]); */
	/* printf("\n"); */
	/* TODO: THIS SIZE IS HARDCODED!!! */
	int uchar_shares_len = ia.secpar/8;
	uchar_shares[i] = calloc(uchar_shares_len, sizeof(unsigned char));	
	for (int j = 0; j < uchar_shares_len; j++) {
	    uchar_shares[i][j] = sym_enc_shares[i][j] ^ key[j];
	}
	printf("Decrypted Shares: ");
	for (int j = 0; j < uchar_shares_len; j++)
	    printf("%02x ", uchar_shares[i][j]);
	printf("\n");
	shares[i] = BN_new();
	BN_bin2bn(uchar_shares[i], strnlen((char *)uchar_shares[i], MAX_MSG_LEN), shares[i]);
	if (!shares[i]) { return openssl_error("Failed to bin2bn the uchar shares"); }
    }

    /* 4. reconstruct SSS's with the s'_i's to get s' */
    if (ia.threshold > num_entries || ia.threshold < 1) {
	return general_error("Failed to set meaningful threshold");
    }
    BIGNUM *possible_secret;
    unsigned char *possible_secret_digest;
    for (int mask = 0; mask < (1 << num_entries); mask++) {
	if (manual_popcount(mask) == ia.threshold) {
	    /* Fn alloc's possible_secret */
	    r = elgamal_reconstruct_shamir_secret(&possible_secret, shares, ia.threshold,
						  num_entries, mask, server_keys.pk->modulus);
	    if (!r) { return general_error("Failed to reconstruct shamir secret"); }
	    /* 5. hash s' and compare with the hash(s) you received */
	    switch (ia.secpar) {
	    case 1024:
		digest_len = SHA_DIGEST_LENGTH;
		/* Fn alloc's possible_secret_digest */
		r = hash(&possible_secret_digest, possible_secret, "SHA1", digest_len, Bignum);
		break;
	    case 2048:
		digest_len = SHA256_DIGEST_LENGTH;
		r = hash(&possible_secret_digest, possible_secret, "SHA224", digest_len, Bignum);
		break;
	    default:
		digest_len = SHA256_DIGEST_LENGTH;
		r = hash(&possible_secret_digest, possible_secret, "SHA256", digest_len, Bignum);
		break;
	    }
	    if (!r) { return openssl_error("Failed to hash poissble_secret"); }
	    /* printf("%i: \n", mask); */
	    printf("------------------\n");
	    for (int j = 0; j < digest_len; j++)
		printf("%02x ", secret_digest[j]);
	    printf("\n");
	    for (int j = 0; j < digest_len; j++)
		printf("%02x ", possible_secret_digest[j]);
	    printf("\n\n\n");
	    if (0 == memcmp(secret_digest, possible_secret_digest, digest_len)) {
		printf("SUCCESS :)\n");
		break;
	    }
	    BN_free(possible_secret);
	    free(possible_secret_digest);
	}
    }

    for (int i = 0; i < num_entries; i++) {
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
elgamal_client_brute_force_thresholding (
    int                   fd,
    GamalPk        server_pk,
    GamalCiphertext cipher[],
    InputArgs             ia,
    int          num_entries)
{
    int r;
    BN_CTX *ctx = BN_CTX_new();

    /* 1. generate a random secret value 's' */
    BIGNUM *bn_secret;
    bn_secret = BN_new();
    r = BN_rand_range_ex(bn_secret, server_pk.modulus, ia.secpar, ctx);
    if (!r) { return openssl_error("Failed to gen bn_secret"); }

    /* 2. secret share 's' using SSS to generate 'n' shares (s_i) */
    BIGNUM *shares[num_entries];
    if (ia.threshold > num_entries || ia.threshold < 1) {
	return general_error("Failed to set meaningful threshold");
    }
    /* Fn alloc's num_entries shares */
    r = elgamal_construct_shamir_shares(shares, bn_secret, ia.secpar, ia.threshold,
					num_entries, server_pk.modulus);
    if (!r) { return general_error("Failed to construct shamir shares"); }
    unsigned char *uchar_shares[num_entries];
    for (int i = 0; i < num_entries; i++) {
	printf("Shares: ");
	uchar_shares[i] = calloc(BN_num_bytes(shares[i]), sizeof(unsigned char));
	BN_bn2bin(shares[i], uchar_shares[i]);
	if (!(uchar_shares + i)) { return openssl_error("Failed to bn2bin the shares"); }
	for (int j = 0; j < BN_num_bytes(shares[i]); j++)
	    printf("%02x ", uchar_shares[i][j]);
	printf("\n");
    }

    /* 3. hash (cipher[i].c2) and store into cipher_hashes[i] */
    unsigned char *cipher_digests[num_entries];
    unsigned char *secret_digest;
    size_t digest_len;
    for (int i = 0; i < num_entries; i++) {
	switch (ia.secpar) {
	case 1024:
	    digest_len = SHA_DIGEST_LENGTH;
	    /* Fn alloc's cipher_digests[i] */
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA1", digest_len, Bignum);
	    r &= hash(&secret_digest, bn_secret, "SHA1", digest_len, Bignum);
	    break;
	case 2048:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA224", digest_len, Bignum);
	    r &= hash(&secret_digest, bn_secret, "SHA224", digest_len, Bignum);
	    break;
	default:
	    digest_len = SHA256_DIGEST_LENGTH;
	    r = hash(&cipher_digests[i], cipher[i].c2, "SHA256", digest_len, Bignum);
	    r &= hash(&secret_digest, bn_secret, "SHA256", digest_len, Bignum);
	    break;
	}
	if (!r) { return openssl_error("Failed to hash cipher[i].c2 or secret"); }
	printf("Keys ------>: ");
	for (int j = 0; j < digest_len; j++)
	    printf("%02x ", cipher_digests[i][j]);
	printf("\n");
    }

    /* 4. Encrypt (s_i) with AES using arr[i] as key */
    unsigned char *key;
    unsigned char *sym_enc_shares[num_entries];
    size_t sym_enc_share_lens[num_entries];
    for (int i = 0; i < num_entries; i++) {
	key = cipher_digests[i];
	sym_enc_shares[i] = calloc(digest_len, sizeof(unsigned char));
	for (int j = 0; j < digest_len; j++) {
	    if (j < BN_num_bytes(shares[i])) {
		sym_enc_shares[i][j] = key[j] ^ uchar_shares[i][j];
	    } else {
		sym_enc_shares[i][j] = key[j];
	    }
	}
	sym_enc_share_lens[i] = digest_len;
	/* printf("sym_enc_share_lens[%i] = %lu\n\n", i, sym_enc_share_lens[i]); */
	printf("Encrypted Shares: ");
	for (int j = 0; j < sym_enc_share_lens[i]; j++)
	    printf("%02x ", sym_enc_shares[i][j]);
	printf("\n");
    }

    /* 5. send iv's, output of (4), and hash(s) to server */
    for (int i = 0; i < num_entries; i++) {
	r = send_msg(fd, &sym_enc_share_lens[i], "Client sent cipher share len:", SizeT);
	if (!r) { return general_error("Failed to send sym_enc_share_lens[i]"); }
	r = send_msg(fd, sym_enc_shares[i], "Client sent cipher share:", UnsignedChar,
		     sym_enc_share_lens[i]);
	if (!r) { return general_error("Failed to send ciphertext_shares[i]"); }
    }
    /* printf("\n\nsecret digest length is %zu\n\n", digest_len); */
    r = send_msg(fd, secret_digest, "Client sent secret digest:", UnsignedChar, digest_len);
    if (!r) { return general_error("Failed to send secret digest"); }

    for (int i = 0; i < num_entries; i++) {
	free(uchar_shares[i]);
	free(sym_enc_shares[i]);
    }
    BN_CTX_free(ctx);
    if (!r) {
	return FAILURE;
    }
    return SUCCESS;
}
