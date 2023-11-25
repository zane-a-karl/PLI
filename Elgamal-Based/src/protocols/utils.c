#include <stdlib.h>	                // size_t
#include <openssl/bn.h>	                // BIGNUM
#include "../../hdr/input-args/utils.h" // InputArgs
#include "../../hdr/macros.h"           // MAX_FILENAME_LEN
#include "../../hdr/protocols/utils.h"
#include "../../hdr/error/utils.h"      // general_error()
/* PLI */
#include "../../hdr/protocols/PLI-elgamal-ah.h"
#include "../../hdr/protocols/PLI-elgamal-mh.h"
#include "../../hdr/protocols/PLI-ecelgamal-ah.h"
/* #include "../../hdr/PLI-ecelgamal-mh.h" */
/* PLIca */
#include "../../hdr/protocols/PLIca-elgamal-ah.h"
#include "../../hdr/protocols/PLIca-elgamal-mh.h"
#include "../../hdr/protocols/PLIca-ecelgamal-ah.h"
/* #include "../../hdr/protocols/PLIca-ecelgamal-mh.h" */
/* tPLI */
#include "../../hdr/protocols/tPLI-elgamal-ah.h"
#include "../../hdr/protocols/tPLI-elgamal-mh.h"
#include "../../hdr/protocols/tPLI-ecelgamal-ah.h"
/* #include "../../hdr/protocols/tPLI-ecelgamal-mh.h" */
/* tPLIca */
#include "../../hdr/protocols/tPLIca-elgamal-ah.h"
#include "../../hdr/protocols/tPLIca-elgamal-mh.h"
#include "../../hdr/protocols/tPLIca-ecelgamal-ah.h"
/* #include "../../hdr/protocols/tPLI-ecelgamal-mh.h" */


/** To add a new protocol:
 * [1] add a src and hdr file following the naming convention
 * <pli-method>-<elgamal-flavor>-<homomorphism-type>.c/h
 * [2] make sure the header guards match the naming convention as well just with '_'s
 * [3] make sure the function names match those in the lookup hash table below
 * [4] make sure the include statements are correct
 *
 * NOTE: If you ever want to add OPRF protocols, the bloom filter protocol, etc. You can extend
 * the Elgamal-flavors or merge the eflavs and the homomorphism types into eg-mh, eg-ah, eceg-ah,
 * etc. For now this is fine.
 */
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
		client_run_t_pli_elgamal_ah,//htype = 0 = AH
		client_run_t_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		client_run_t_pli_ecelgamal_ah,//htype = 0 = AH
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
		client_run_t_pli_ca_elgamal_ah,//htype = 0 = AH
		client_run_t_pli_ca_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		client_run_t_pli_ca_ecelgamal_ah,//htype = 0 = AH
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
		NULL,//htype = 1 = MH
	    }
	},
	{//pmeth = 1 = PLIca
	    {//eflav = 0 = EG
		server_run_pli_ca_elgamal_ah,//htype = 0 = AH
		server_run_pli_ca_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		server_run_pli_ca_ecelgamal_ah,//htype = 0 = AH
		NULL,//htype = 1 = MH
	    }
	},
	{//pmeth = 2 = tPLI
	    {//eflav = 0 = EG
		server_run_t_pli_elgamal_ah,//htype = 0 = AH
		server_run_t_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		server_run_t_pli_ecelgamal_ah,//htype = 0 = AH
		NULL,//htype = 1 = MH
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
		server_run_t_pli_ca_elgamal_ah,//htype = 0 = AH
		server_run_t_pli_ca_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		server_run_t_pli_ca_ecelgamal_ah,//htype = 0 = AH
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
    InputArgs   ia)
{
    int r = pp(fd, ia);
    if (!r) { return general_error("Failed during execution of run()"); }
    return SUCCESS;
}
