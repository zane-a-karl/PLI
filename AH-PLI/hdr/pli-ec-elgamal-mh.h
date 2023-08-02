#ifndef _PLI_EC_ELGAMAL_MH_H_
#define _PLI_EC_ELGAMAL_MH_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep()
#include "utils.h"
#include "ec-elgamal/utils.h"
#include "ec-elgamal/mh-utils.h"


int
server_run_pli_ec_elgamal_mh (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_pli_ec_elgamal_mh (
    int                  sockfd,
    int                 sec_par,
    char *             filename);

#endif//_PLI_EC_ELGAMAL_MH_H_
