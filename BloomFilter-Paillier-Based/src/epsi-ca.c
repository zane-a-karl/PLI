#include "../hdr/epsi-ca.h"



#define BLOOM_FILE "input/bloom.txt"

int
server_run_epsi_ca (
    int                          new_fd,
    int                     num_entries,
    paillier_plaintext_t **list_entries,
    paillier_keys_t         server_keys,
    paillier_pubkey_t         client_pk)
{
    int                          r;
    bloom_filter_t              bf;
    char                      *buf;
    const unsigned int bf_capacity = 1000;
    const double        bf_fp_rate = .001;

    /** STEP 1
     * [setup] The parties perform a secure coin-tossing sub-protocol to choose random seeds
     * for Bloom filter hash functions h1 , . . . , hk : {0, 1}∗ -> [N].
     */
    /* r = server_run_coin_toss(); */
    /* Not sure what the best is here but libbloom requires >= 1000 capacity and 0<fpr<1 */
    r = bloom_init2(&bf, bf_capacity, bf_fp_rate);
    if (r == 1) { return general_error("Failed to init bloom filter"); }
    if (!bf.ready) { return general_error("Failed to ready bloom filter"); }
    /* TODO: This should also probably be a bloom_load() call because you will get a race
     condition with the client when trying to access the bloom filter and if the client wins
     then she gets an empty or non-existant file */
    /* r = bloom_save(&bf, BLOOM_FILE); */
    r = bloom_load(&bf, BLOOM_FILE);
    if (r == 1) { return general_error("Failed to load bloom filter"); }
    bloom_print(&bf);

    /** STEP 2
     * [P2 encrypts its Bloom filter] P2 builds an N-bit Bloom filter of his set S using
     * h1, . . . , hk, encrypts the bits of the Bloom filter under pk2, and sends the
     * resulting encrypted bits e1, e2, . . . , eN to P1.
     */
    buf = calloc(MAX_MSG_LEN, sizeof(char));
    /* enc_spk_bf = calloc(num_entries, sizeof(*enc_spk_bf)); */
    for (int i = 0; i < num_entries; i++) {
	r = serialize_paillier_ptxt(&buf, list_entries[i]);
	if (!r) { return general_error("Failed to serialize paillier plaintext"); }
	r = bloom_add(&bf, buf, strnlen(buf, MAX_MSG_LEN));
	/* r == 1 => value already in bf
	   r == 0 => value successfully added */
	if (r == -1) { return general_error("Failed to add ptxt, bf not initialized"); }
    }
    paillier_ciphertext_t *enc_spk_bf_bits[bf.bits];
    paillier_plaintext_t          *bf_bits[bf.bits]; // TODO: free() this memory!!!
    int bits_in_uc = 8 * sizeof(unsigned char);
    int bf_bits_i;
    int bits_left_in_byte;
    printf("Started sending enc spk bf bits\n"); /* TTICK; */
    for (int i = 0; i < bf.bytes; i++) {
	if (i == bf.bytes-1) {
	    bits_left_in_byte = bf.bits % bits_in_uc;
	} else {
	    bits_left_in_byte = bits_in_uc;
	}
	for (int j = 0; j < bits_left_in_byte; j++) {
	    bf_bits_i = bits_in_uc * i + j;
	    if ( ( bf.bf[i] >> (bits_in_uc-1 - j) ) & 1 ) {
		bf_bits[bf_bits_i] = paillier_plaintext_from_ui(1UL);
	    } else {
		bf_bits[bf_bits_i] = paillier_plaintext_from_ui(0UL);
	    }
	    enc_spk_bf_bits[bf_bits_i] = paillier_create_enc_zero();
	    paillier_enc(enc_spk_bf_bits[bf_bits_i], server_keys.pk, bf_bits[bf_bits_i],
			 paillier_get_rand_devurandom);
	    r = send_msg(new_fd, enc_spk_bf_bits[bf_bits_i], "Server: sent bf ctxt", 0,
			 PaillierCiphertext);
	    if (!r) { return general_error("Failed to send_msg()"); }
	}
    }
    printf("Finished sending enc spk bf bits\n\n"); /* TTICK; */

    /** Step 3 */
    paillier_ciphertext_t *enc_spk_indexes[num_entries]; // TODO: free() this memory!!!!
    printf("Started receiving enc spk indexes\n");
    for (int i = 0; i < num_entries; i++) {
	enc_spk_indexes[i] = paillier_create_enc_zero();
	r = recv_msg(new_fd, enc_spk_indexes[i], "Server: recv enc spk indexes", 1,
		     PaillierCiphertext);
	if (!r) { return general_error("Failed to recv enc spk indexes"); }
    }
    printf("Finished receiving enc spk indexes\n\n");

    /** Step 4 */

    /** Step 5
     * [output] P2 decrypts enˆ to get nˆi . P2 obliviously evaluates (k!)−1 ·( pi (nˆi )) ii
     * via additive homomorphism. Outputs this encrypted result.
     */

    return SUCCESS;
}

int
client_run_epsi_ca (
    int                          sockfd,
    int                     num_entries,
    paillier_plaintext_t **list_entries,
    paillier_keys_t         client_keys,
    paillier_pubkey_t         server_pk)
{
    int                          r;
    bloom_filter_t              bf;  // TODO: free() this memory!!!!
    const unsigned int bf_capacity = 1000;
    const double        bf_fp_rate = .001;
    /* Perform secure coin tossing protocol to random seeds for bloom filter hash fns */
    /* r = client_run_coin_toss(); */
    r = bloom_init2(&bf, bf_capacity, bf_fp_rate);
    if (r == 1) { return general_error("Failed to init bloom filter"); }
    if (!bf.ready) { return general_error("Failed to ready bloom filter"); }
    r = bloom_load(&bf, BLOOM_FILE);
    if (r == 1) { return general_error("Failed to load bloom filter"); }
    bloom_print(&bf);

    paillier_ciphertext_t *enc_spk_bf_bits[bf.bits];  // TODO: free() this memory!!!!
    printf("Started receiving enc spk bf bits\n"); /* TTICK; */
    for (int i = 0; i < bf.bits; i++) {
	enc_spk_bf_bits[i] = paillier_create_enc_zero();
	r = recv_msg(sockfd, enc_spk_bf_bits[i], "Client: recv bf bits ctxt", 0,
		     PaillierCiphertext);
	if (!r) { return general_error("Failed to recv_msg()"); }
    }
    printf("Finished receiving enc spk bf bits\n\n"); /* TTICK; */

    /** Step 3
     * [P1 masks the query results] For each element ci ∈ C, P1 hashes ci using those k hash
     * functions to obtain k indices h1(ci), h2(ci), . . . , hk(ci). P1 creates a ciphertext
     * e_n_i to be sent to P2 by homomorphically summing up all i ciphertexts at those indices
     * (e_h1(ci),...,e_hk(ci)) and another ciphertext of a randomly chosen number ri.
     */
    unsigned long indexes[num_entries][bf.hashes];
    paillier_plaintext_t *pptxt_indexes[num_entries][bf.hashes];  // TODO: free() this memory!!!!
    paillier_ciphertext_t *enc_spk_indexes[num_entries];  // TODO: free() this memory!!!!
    paillier_ciphertext_t *intermediate = paillier_create_enc_zero();  // TODO: free() this memory!!!!
    mpz_t masks[num_entries];  // TODO: free() this memory!!!!
    paillier_plaintext_t *pptxt_mask;  // TODO: free() this memory!!!!
    /* Required to use libgmp for randomness generation */
    gmp_randstate_t state;
    int base16 = 16;
    char *mask_str;
    gmp_randinit_default (state);
    printf("Started sending enc spk indexes\n");
    for (int i = 0; i < num_entries; i++) {
	r = get_murmur2hash_indexes(indexes[i], list_entries[i], sizeof(list_entries[i]), &bf);
	if (!r) { return general_error("Failed to get murmur2hash indexes"); }
	enc_spk_indexes[i] = paillier_create_enc_zero();
	for (int j = 0; j < bf.hashes; j++) {
	    pptxt_indexes[i][j] = paillier_plaintext_from_ui(indexes[i][j]);
	    paillier_enc(intermediate, &server_pk, pptxt_indexes[i][j],
			 paillier_get_rand_devurandom);
	    /* Libpaillier uses _mul() for the homomorphic addition of ctxts */
	    paillier_mul(&server_pk, enc_spk_indexes[i], enc_spk_indexes[i], intermediate);
	}
	mpz_init(masks[i]);
	mpz_urandomm (masks[i], state, server_pk.n_squared);
	mask_str = mpz_get_str(NULL, base16, masks[i]);
	pptxt_mask = paillier_plaintext_from_str(mask_str);
	/* mask_str gets alloc'd by mpz_get_str() so free here prevents mem leak */
	free(mask_str);
	paillier_enc(intermediate, &server_pk, pptxt_mask, paillier_get_rand_devurandom);
	/* pptxt_mask gets alloc'd by p_enc() so free here prevents mem leak */	
	paillier_freeplaintext(pptxt_mask);
	paillier_mul(&server_pk, enc_spk_indexes[i], enc_spk_indexes[i], intermediate);

	r = send_msg(sockfd, enc_spk_indexes[i], "Client: sent enc spk indexes", 1,
		     PaillierCiphertext);
	if (!r) { return general_error("Failed to send enc spk indexes"); }
    }
    printf("Finished sending enc spk indexes\n\n");


    /** Step 4
     * [P1 prepares encrypted polynomials] For all i, P1 encrypts under pk1 the coefficients
     * of a degree-k polynomial pi(x) = (x−ri)(x−ri−1) · · · (x−ri−k+1). P1 sends the encrypted
     * coefficients of pi(·) and e_n_i to P2.
     */

    /** Step 5 */

    return SUCCESS;
}
