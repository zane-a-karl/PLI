#include "../hdr/pli.h"


extern uint64_t total_bytes;
static struct timespec t1,t2;
static double sec;
static FILE *logfs;
static char *logfile;

/* #define TSTART(sec_par)							\ */
/*     logfile = calloc(32, sizeof(char));					\ */
/*     snprintf(logfile, 32, "%s-%d.%s", "logs/bf-paillier", sec_par, "csv"); \ */
/*     logfs = fopen(logfile, "a");					\ */
/*     printf("Starting the clock: \n");					\ */
/*     clock_gettime(CLOCK_MONOTONIC, &t1); */
#define TSTART(sec_par)		      \
    logfs = stdout;		      \
    printf("Starting the clock: \n"); \
    clock_gettime(CLOCK_MONOTONIC, &t1);

#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2);			\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs,"Line:%5d, Time = %f\n",__LINE__,sec);

#define COLLECT_LOG_ENTRY(sec_par, n_entries, bytes)			\
    printf("Ending the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t2);				\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs, "%d, ", sec_par);					\
    fprintf(logfs, "%d, ", n_entries);					\
    fprintf(logfs, "%" PRIu64 ", ", bytes);				\
    fprintf(logfs,"%f\n", sec);						\
    fclose(logfs);

int
server_run_bf_paillier_pli (
    int     new_fd,
    int    sec_par,
    char *filename)
{
    int r;
    int num_entries;
    paillier_keys_t  server_keys;
    paillier_pubkey_t client_pk;    
    paillier_plaintext_t **list_entries;

    /* Generate Keys */
    printf("Started generating server keys\n");
    paillier_keygen(sec_par, &server_keys.pk, &server_keys.sk, paillier_get_rand_devurandom );
    if (!server_keys.pk) { return general_error("Failed to gen PaillierPubkey"); }
    if (!server_keys.sk) { return general_error("Failed to gen PaillierPrvkey"); }
    printf("Finished generating server keys\n\n");

    /* Start timing here to exclude key generation */
    TSTART(sec_par);

    /* Parse number of list entries from <filename> */
    num_entries = 0;
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Parse server list entries from <filename> */
    list_entries = calloc(num_entries, sizeof(*list_entries));
    /* Fn alloc's paillier plaintext entries */
    r = parse_file_for_list_entries(list_entries, num_entries, filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }
    printf("Parsed server list\n");

    /* Send server pk to client */
    printf("Started sending server pk\n"); TTICK;
    r = send_msg(new_fd, server_keys.pk, "Server: sent server pk", 1, PaillierPubkey);
    if (!r) { return general_error("Failed to send server pk"); }
    printf("Finished sending server pk\n\n"); TTICK;

    /* Receive client pk from client */
    printf("Started receiving client pk\n");
    r = recv_msg(new_fd, &client_pk, "Client: received client pk", 1, PaillierPubkey);
    if (!r) { return general_error("Failed to recv client pk"); }
    printf("Finished receiving client pk\n");

    /* Start ePSI-CA */
    r = server_run_epsi_ca(new_fd, num_entries, list_entries, server_keys, client_pk);
    if (!r) { return general_error("Failed during execution of epsi_ca"); }
    /* Finish ePSI-CA */
    exit(1);

    /* Encrypt server list entries and send them to client */
    /* printf("Started sending Enc_pkS(server list)\n"); TTICK; */
    /* server_cipher = calloc(num_entries, sizeof(*server_cipher)); */
    for (int i=0; i < num_entries; i++) {
    }
    /* printf("Finished sending Enc_pkS(server list)\n\n"); TTICK; */

    /* Receive exp_res entries from client */
    /* printf("Started receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n"); TTICK; */
    /* client_cipher = calloc(num_entries, sizeof(*client_cipher)); */
    for (int i=0; i<num_entries; i++) {
    }
    /* printf("Finished receiving masked Enc_pkS(server list) * Enc_pkS(inv client list)\n\n"); TTICK; */

    /* Skip decryption and just check c2 == c1^sk */
    /* printf("Started pli ciphertext comparison\n"); TTICK; */
    for (int i=0; i<num_entries; i++) {
    }
    /* printf("Finished pli ciphertext comparison\n\n"); TTICK; */
    /* printf("Total bytes sent during protocol = %" PRIu64 "\n", total_bytes); */
    /* COLLECT_LOG_ENTRY(sec_par, num_entries, total_bytes); */

    free(logfile);
    if (!r) { return FAILURE; }
    return SUCCESS;
}

int
client_run_bf_paillier_pli (
    int     sockfd,
    int    sec_par,			    
    char *filename)
{
    int r;
    int num_entries;
    paillier_keys_t client_keys;
    paillier_pubkey_t server_pk;
    paillier_plaintext_t **list_entries;

    /* Parse number of list entries from <filename> */
    num_entries = 0;
    r = parse_file_for_num_entries(&num_entries, filename);
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    /* Parse client list entries from <filename> */
    list_entries = calloc(num_entries, sizeof(*list_entries));
    /* Fn alloc's paillier plaintext entries */
    r = parse_file_for_list_entries(list_entries, num_entries, filename);
    if (!r) { return general_error("Failed to parse file for list entries"); }
    printf("parsed client list\n");

    /* Receive server pk from server */
    printf("Started receiving server pk\n");
    r = recv_msg(sockfd, &server_pk, "client: received server pk", 1, PaillierPubkey);
    if (!r) { return general_error("Failed to recv server pk"); }
    printf("Finished receiving server pk\n");

    /* Generate Keys */
    printf("Started generating client keys\n");
    paillier_keygen(sec_par, &client_keys.pk, &client_keys.sk, paillier_get_rand_devurandom);
    if (!client_keys.pk) { return general_error("Failed to gen PaillierPubkey"); }
    if (!client_keys.sk) { return general_error("Failed to gen PaillierPrvkey"); }
    printf("Finished generating client keys\n\n");

    /* Send client pk to server */
    printf("Started sending client pk\n"); /* TTICK; */
    r = send_msg(sockfd, client_keys.pk, "Client: sent client pk", 1, PaillierPubkey);
    if (!r) { return general_error("Failed to send client pk"); }
    printf("Finished sending client pk\n\n"); /* TTICK; */

    /* Start ePSI-CA */
    r = client_run_epsi_ca(sockfd, num_entries, list_entries, client_keys, server_pk);
    if (!r) { return general_error("Failed during execution of epsi_ca"); }
    /* Finish ePSI-CA */
    exit(1);

    /* Receive ciphertext in two sequential messages of c1 and c2 */
    /* printf("Started receiving Enc_pkS(server list)\n"); TTICK; */
    /* server_cipher = calloc(num_entries, sizeof(*server_cipher)); */
    for (int i = 0; i < num_entries; i++) {
    }
    /* printf("Finished receiving Enc_pkS(server list)\n\n"); TTICK; */

    /* Calculate the negation/mult inv of the client list entries */
    /* printf("Started computing (Enc_pkS(server list) * Enc_pkS(inv client list))^mask \n"); TTICK; */
    for (int i = 0; i < num_entries; i++) {
    }
    /* Encrypt inverse of client list entries under the server public key */
    /* client_cipher = calloc(num_entries, sizeof(*client_cipher)); */
    for (int i = 0; i < num_entries; i++) {
    }

    /* Multiply the server and client ciphertexts */
    /* GamalCiphertext mul_res[num_entries]; */
    for (int i = 0; i < num_entries; i++) {
    }

    /* Generate a random masking value */
    /* BIGNUM *bn_rand_mask[num_entries]; */
    for (int i = 0; i < num_entries; i++) {
    }
    /* printf("generated random masking value\n"); */

    /* Raise product of ciphertext to the random value 'bn_rand_mask' */
    /* GamalCiphertext exp_res[num_entries]; */
    for (int i = 0; i < num_entries; i++) {
    }
    /* printf("Finished computing (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */

    /* Send exp_res to the server */
    /* printf("Started sending (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */
    for (int i = 0; i < num_entries; i++) {
    }
    /* printf("Finished sending (Enc_pkS(server list) * Enc_pkS(inv client list))^mask\n"); TTICK; */

    if (!r) { return FAILURE; }
    return SUCCESS;
}
