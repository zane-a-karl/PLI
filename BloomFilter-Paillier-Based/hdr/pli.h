#ifndef _PLI_H_
#define _PLI_H_

#include <string.h>     // memset()
#include <sys/socket.h> // send() ,  recv()
#include <sys/wait.h>   // wait()
#include <time.h>       // clock_gettime()
#include <unistd.h>     // close(), sleep(), fork()
#include "../hdr/utils.h"
#include "../hdr/bfp-utils.h"
#include "../hdr/epsi-ca.h"


int
server_run_bf_paillier_pli (
    int     new_fd,
    int    sec_par,
    char *filename);

int
client_run_bf_paillier_pli (
    int     sockfd,
    int    sec_par,
    char *filename);

#endif//_PLI_H_
