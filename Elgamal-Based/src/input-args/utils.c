#include <stdlib.h>           // size_t
#include <openssl/bn.h>       // BIGNUM
#include "../../hdr/macros.h" // SUCCESS
#include "../../hdr/input-args/utils.h"
#include "../../hdr/error/utils.h" // general_error()
#include <getopt.h>		   // struct option
#include <string.h> 		   // strncmp()
#include <ctype.h>		   // toupper()


/**
 *
 */
int
parse_input_args (
    InputArgs        *ia,
    int             argc,
    char          **argv,
    enum PartyType party)
{
    int r;
    int c;

    /* Setup ia defaults */
    ia->hostname  = "localhost";
    ia->pmeth     = PLI;
    ia->eflav     = ECEG;
    ia->htype     = AH;
    ia->secpar    = 64UL;
    ia->threshold = 0;
    ia->expected_matches = 0;
    ia->client_filename  = "input/client.txt";
    ia->server_filename  = "input/server.txt";
    if (party == CLIENT) {
	/* TODO: use stdlib system() to call ./setup_default_client_file.sh */
	r = parse_file_for_num_entries(&ia->num_entries, ia->client_filename);
    } else {
	/* TODO: use stdlib system() to call ./setup_default_server_file.sh */
	r = parse_file_for_num_entries(&ia->num_entries, ia->server_filename);
    }
    if (!r) { return general_error("Failed to parse file for number of list entries"); }

    int option_index = 0;
    static struct option long_options[] =
	{
	    {"hostname",           required_argument, NULL, 'h'},
	    {"pli-method",         required_argument, NULL, 'p'},
	    {"elgamal-flavor",     required_argument, NULL, 'e'},
	    {"homomorphism-type",  required_argument, NULL, 'm'},
	    {"security-parameter", required_argument, NULL, 'y'},
	    {"list-length",        required_argument, NULL, 'n'},
	    {"threshold",          required_argument, NULL, 't'},
	    {"expected-matches",   required_argument, NULL, 'x'},
	    {"client-filename",    required_argument, NULL, 'c'},
	    {"server-filename",    required_argument, NULL, 's'},
	    {"log-filename",       required_argument, NULL, 'l'},
	    {0, 0, 0, 0}
	};
    while (1) {
	c = getopt_long(argc, argv, "h:p:e:m:y:n:t:x:c:s:l:", long_options, &option_index);
	/* Detect the end of the options. */
	if (c == -1) { break; }
	switch (c) {
        case 0:
	    if (long_options[option_index].flag != 0) { break; }
	    printf("option %s", long_options[option_index].name);
	    if (optarg) {
		printf(" with arg %s", optarg);
	    }
	    printf("\n");
	    break;
        case 'h':
	    printf("option -h with value `%s'\n", optarg);
	    ia->hostname = optarg;
	    break;
        case 'p':
	    printf("option -p with value `%s'\n", optarg);
	    r = str_to_pli_method(&ia->pmeth, optarg);
	    if (!r) { return general_error("Failed to parse pli method"); }
	    break;
        case 'e':
	    printf("option -e with value `%s'\n", optarg);
	    r = str_to_elgamal_flavor(&ia->eflav, optarg);
	    if (!r) { return general_error("Failed to parse elgamal flavor"); }
	    break;
        case 'm':
	    printf("option -m with value `%s'\n", optarg);
	    r = str_to_homomorphism_type(&ia->htype, optarg);
	    if (!r) { return general_error("Failed to parse homomorphism type"); }
	    break;
        case 'y':
	    printf("option -y with value `%s'\n", optarg);
	    r = str_to_size_t(&ia->secpar, optarg);
	    if (!r) { return general_error("Failed to parse secpar"); }
	    break;
        case 'n':
	    printf("option -n with value `%s'\n", optarg);
	    size_t n = 0;
	    r = str_to_size_t(&n, optarg);
	    if (!r) { return general_error("Failed to parse list_len"); }
	    if (n != ia->num_entries) { return general_error(""); }
	    break;
        case 't':
	    printf("option -t with value `%s'\n", optarg);
	    r = str_to_size_t(&ia->threshold, optarg);
	    if (!r) { return general_error("Failed to parse threshold"); }
	    break;
        case 'x':
	    printf("option -x with value `%s'\n", optarg);
	    r = str_to_size_t(&ia->expected_matches, optarg);
	    if (!r) { return general_error("Failed to parse expected_matches"); }
	    break;
        case 'c':
	    printf("option -c with value `%s'\n", optarg);
	    ia->client_filename = optarg;
	    break;
        case 's':
	    printf("option -s with value `%s'\n", optarg);
	    ia->server_filename = optarg;
	    break;
        case 'l':
	    printf("option -l with value `%s'\n", optarg);
	    ia->log_filename = optarg;
	    break;
        case '?':
	    /* getopt_long returns its own error message */
        default:
	    printf("Usage: %s", argv[0]);
	    printf("--hostname           -h <hostname>\n");
	    printf("--pli-method         -p <pli method>\n");
	    printf("--elgamal-flavor     -e <EG or ECEG>\n");
	    printf("--homomorphism-type  -m <MH or AH>\n");
	    printf("--security-parameter -y <security parameter>\n");
	    printf("--list-len           -n <list-len>\n");
	    printf("--threshold          -t <threshold>\n");
	    printf("--expected-matches   -x <expected-matches>\n");
	    printf("--client-filename    -c <client-filename>\n");
	    printf("--server-filename    -s <server-filename>\n");
	    return general_error("Failed to follow correct program usage");
        } /* switch */
    } /* while */

    /* Print any remaining command line arguments (not options). */
    if (optind < argc) {
	printf("non-option ARGV-elements: ");
	while (optind < argc) {
	    printf("%s ", argv[optind++]);
	}
	putchar('\n');
    }
    if ( ia->pmeth == t_PLI || ia->pmeth == t_PLI_ca || ia->pmeth == t_PLI_x ) {
	if (!ia->threshold) {
	    return general_error("Failed to match PLI method with threshold");
	} else if (ia->threshold > ia->num_entries || ia->threshold < 1) {
	    return general_error("Failed to set meaningful threshold");
	}
    }
    if (ia->secpar < 8) {
	return general_error("Failed provide meaningful security parameter");
    }
    if ( ia->eflav == ECEG && ia->htype == MH ) {
	return general_error("Library does not yet implement ECEG with MH");
    }
    if ( ia->eflav == ECEG && ia->secpar > 224 ) {
	return general_error("Library's largest curve lies in a 224-bit field");
    }
    if (strncmp(ia->log_filename, "", MAX_FILENAME_LEN) == 0) {
	ia->log_filename = "stdout";
	perror("WARNING: logging file not specified and set by default to stdout");
    }

    return SUCCESS;
}

/**
 *
 */
int
str_to_pli_method (
    enum PliMethod *pm,
    char          *str)
{
    const int max_pmeth_str_len = 9;
    if ( 0 == strncmp(str, "PLI", max_pmeth_str_len) ) {
	*pm = PLI;
    } else if ( 0 == strncmp(str, "PLIca", max_pmeth_str_len) ) {
	*pm = PLI_ca;
    } else if ( 0 == strncmp(str, "tPLI", max_pmeth_str_len) ) {
	*pm = t_PLI;
    } else if ( 0 == strncmp(str, "PLIx", max_pmeth_str_len) ) {
	*pm = PLI_x;
    } else if ( 0 == strncmp(str, "tPLIca", max_pmeth_str_len) ) {
	*pm = t_PLI_ca;
    } else if ( 0 == strncmp(str, "tPLIx", max_pmeth_str_len) ) {
	*pm = t_PLI_x;
    } else {
	printf("Error: Input must match one of {PLI, PLIca, tPLI, PLIx, tPLIca, tPLIx} exactly\n");
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_homomorphism_type (
    enum HomomorphismType *ht,
    char                 *str)
{
    const int max = 3;
    for (int i = 0; i < strnlen(str, max); i++) {
	str[i] = toupper(str[i]);
    }
    if ( 0 == strncmp(str, "AH", max) ) {
	*ht = AH;
    } else if ( 0 == strncmp(str, "MH", max) ) {
	*ht = MH;
    } else {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_elgamal_flavor (
    enum ElgamalFlavor *ef,
    char              *str)
{
    const int max = 10;
    for (int i = 0; i < strnlen(str, max); i++) {
	str[i] = tolower(str[i]);
    }
    if ( 0 == strncmp(str, "elgamal", max) ||
	 0 == strncmp(str, "eg", max)) {
	*ef = EG;
    } else if ( 0 == strncmp(str, "ecelgamal", max) ||
		0 == strncmp(str, "eceg", max)) {
	*ef = ECEG;
    } else {
	return FAILURE;
    }
    return SUCCESS;
}

/**
 *
 */
int
str_to_size_t (
    size_t *output,
    char    *input)
{
    int r = sscanf(input, "%lu", output);
    if (!r) { return FAILURE; }
    return SUCCESS;
}

/**
 *
 */
int
parse_file_for_num_entries (
    size_t *num_entries,
    char      *filename)
{
    FILE *fin;
    int c, r, i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	return general_error("Failed to open input file");
    }

    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		c = fgetc(fin);
	    } while(isdigit(c));
	    i++;
	}
    } while (!feof(fin) && !ferror(fin));
    *num_entries = i;

    r = fclose(fin);
    if (r == EOF) {
	return general_error("Failed to close input file");
    }
    return SUCCESS;
}

/**
 *
 */
int
parse_file_for_list_entries (
    BIGNUM      **entries,
    int       num_entries,
    char        *filename)
{
    FILE *fin;
    char *buf = calloc(MAX_FILE_BYTES, sizeof(char));
    int c, r;
    int entries_i = 0, buf_i = 0;

    fin = fopen(filename, "r");
    if (!fin) {
	return general_error("Failed to open input file");
    }

    memset(buf, 0, MAX_FILE_BYTES);
    do {
	c = fgetc(fin);
	if (isdigit(c)) {
	    do {
		buf[buf_i++] = c;
		c = fgetc(fin);
	    } while(isdigit(c));
	    entries[entries_i] = BN_new();
	    if (!entries[entries_i]) {r = 0; return openssl_error("Failed to alloc bn_plain"); }
	    r = BN_dec2bn(&entries[entries_i], buf);
	    if (!r) { return openssl_error("Failed to dec2bn entries"); }
	    entries_i++;
	    memset(buf, 0, MAX_FILE_BYTES);
	    buf_i = 0;
	}
    } while (!feof(fin) && !ferror(fin));

    /* for (int i = 0; i < num_entries; i++) { */
    /* 	printf("entries[%i] = ", i); BN_print_fp(stdout, entries[i]); printf("\n"); */
    /* } */
    free(buf);
    r = fclose(fin);
    if (r == EOF) {
	return general_error("Failed to close input file");
    }
    return SUCCESS;
}
