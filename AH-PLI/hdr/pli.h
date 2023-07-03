#ifndef _PLI_H_
#define _PLI_H_

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep()
#include "../hdr/utils.h"
#include "../hdr/elgamal-utils.h"
#include "../hdr/mh-elgamal.h"
#include "../hdr/ah-elgamal.h"


enum HomomorphismType {
    AH, MH
};

int
server_run_pli (int                  new_fd,
		enum HomomorphismType htype,
		char              *filename);

int
client_run_pli (int                  sockfd,
		enum HomomorphismType htype,
		char              *filename);

#endif//_PLI_H_
