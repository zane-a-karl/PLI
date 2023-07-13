#ifndef _EC_ELGAMAL_PLI_H_
#define _EC_ELGAMAL_PLI_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep()
#include "../hdr/utils.h"
#include "../hdr/ec-elgamal-utils.h"
#include "../hdr/ec-elgamal-mh.h"
#include "../hdr/ec-elgamal-ah.h"


enum HomomorphismType {
    AH, MH
};

int
server_run_ec_elgamal_pli (int                  new_fd,
			   enum HomomorphismType htype,
			   char              *filename);

int
client_run_ec_elgamal_pli (int                  sockfd,
			   enum HomomorphismType htype,
			   char              *filename);

#endif//_EC_ELGAMAL_PLI_H_
