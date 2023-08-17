#include "../../hdr/protocols/utils.h"

/** To add a new protocol:
 * [1] add a src and hdr file following the
 * naming convention
 * [2] make sure the header guards are correct
 * [3] make sure the function names match those
 * in the lookup table below
 * [4] make sure the include statements are
 * correct
 */
// Create a lookup table for combinations
PliProtocol callback[NUM_PARTY_TYPES][NUM_PLI_METHODS][NUM_ELGAMAL_FLAVORS][NUM_HOMOMORPHISM_TYPES]
=
{
    {//client = 0
	{//pmeth = 0 = PLI
	    {//eflav = 0 = EG
		client_run_pli_elgamal_ah,//htype = 0 = AH
		client_run_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		client_run_pli_ecelgamal_ah,//htype = 0 = AH
		NULL,//htype = 1 = MH
	    }
	},
	{//pmeth = 1 = PLIca
	    {//eflav = 0 = EG
		client_run_pli_ca_elgamal_ah,//htype = 0 = AH
		client_run_pli_ca_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		client_run_pli_ca_ecelgamal_ah,//htype = 0 = AH
		NULL,//htype = 1 = MH
	    }
	},
	{//pmeth = 2 = tPLI
	    {//eflav = 0 = EG
		NULL,
		client_run_t_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 3 = PLIx
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 4 = tPLIca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 5 = tPLIx
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	}
    },
    {//server
	{//pmeth = 0 = PLI
	    {//eflav = 0 = EG
		server_run_pli_elgamal_ah,//htype = 0 = AH
		server_run_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		server_run_pli_ecelgamal_ah,//htype = 0 = AH
		server_run_pli_ecelgamal_mh,//htype = 1 = MH
	    }
	},
	{//pmeth = 1 = PLIca
	    {//eflav = 0 = EG
		server_run_pli_ca_elgamal_ah,
		server_run_pli_ca_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		server_run_pli_ca_ecelgamal_ah,//htype = 0 = AH
		NULL,//htype = 1 = MH
	    }
	},
	{//pmeth = 2 = tPLI
	    {//eflav = 0 = EG
		NULL,
		server_run_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 3 = PLIx
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 4 = tPLIca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 5 = tPLIx
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	}
    }
};

int
run (
    PliProtocol pp,
    int         fd,
    int    sec_par,
    char *filename)
{
    int r = pp(fd, sec_par, filename);
    if (!r) { return general_error("Failed during execution of run()"); }
    return SUCCESS;
}

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

int
str_to_int (
    int *output,
    char *input)
{
    int r = sscanf(input, "%d", output);
    if (!r) { return FAILURE; }
    return SUCCESS;
}
