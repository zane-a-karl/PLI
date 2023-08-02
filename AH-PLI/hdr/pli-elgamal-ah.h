#ifndef _PLI_ELGAMAL_AH_H_
#define _PLI_ELGAMAL_AH_H_

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <sys/wait.h>   // wait()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep(), fork()
#include "utils.h"
#include "elgamal/utils.h"
#include "elgamal/ah-utils.h"

int
server_run_pli_elgamal_ah (
    int                  new_fd,
    int                 sec_par,
    char              *filename);

int
client_run_pli_elgamal_ah (
    int                  sockfd,
    int                 sec_par,
    char *             filename);

#endif//_PLI_ELGAMAL_AH_H_
