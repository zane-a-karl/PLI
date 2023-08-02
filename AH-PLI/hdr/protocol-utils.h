#ifndef _PROTOCOL_UTILS_H_
#define _PROTOCOL_UTILS_H_

#include "pli-elgamal-ah.h"
#include "pli-elgamal-mh.h"
#include "pli-ec-elgamal-ah.h"
#include "pli-ec-elgamal-mh.h"

enum PliMethod {
    PLI,
    PLI_ca,
    t_PLI,
    PLI_X,
    t_PLI_ca,
    t_PLI_X,
    NUM_PLI_METHODS
};

/* EG = regular Elgamal,
   ECEG = Elliptic Curve Elgamal */
enum ElgamalFlavor {
    EG,
    ECEG,
    NUM_ELGAMAL_FLAVORS
};

/* AH = additively homomorphic,
   MH = multiplicatively homomorphic */
enum HomomorphismType {
    AH,
    MH,
    NUM_HOMOMORPHISM_TYPES
};


typedef void (*Protocol)(int, int, char *);

const int pt = NUM_PARTY_TYPES;
const int pm = NUM_PLI_METHODS;
const int ef = NUM_ELGAMAL_FLAVORS;
const int ht = NUM_HOMOMORPHISM_TYPES;

// Create a lookup table for combinations
Protocol combinations[pt][pm][ef][ht] =
{
    {//client = 0
	{//pmeth = 0 = PLI
	    {//eflav = 0 = EG
		client_run_pli_elgamal_ah,//htype = 0 = AH
		client_run_pli_elgamal_mh,//htype = 1 = MH
	    },
	    {//eflav = 1 = ECEG
		client_run_pli_ec_elgamal_ah,//htype = 0 = AH
		client_run_pli_ec_elgamal_mh,//htype = 1 = MH
	    }
	},
	{//pmeth = 1 = PLI-ca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 2 = t-PLI
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 3 = PLI-X
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 4 = t-PLI-ca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 5 = t-PLI-X
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
		server_run_pli_ec_elgamal_ah,//htype = 0 = AH
		server_run_pli_ec_elgamal_mh,//htype = 1 = MH
	    }
	},
	{//pmeth = 1 = PLI-ca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 2 = t-PLI
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 3 = PLI-X
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 4 = t-PLI-ca
	    {//eflav = 0 = EG
		NULL,
		NULL,
	    },
	    {//eflav = 1 = ECEG
		NULL,
		NULL,
	    }
	},
	{//pmeth = 5 = t-PLI-X
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
    Protocol pli_method,
    int              fd,
    int         sec_par,
    char      *filename);

#endif//_PROTOCOL_UTILS_H_
