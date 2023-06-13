#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/wait.h>

void *
get_in_addr (struct sockaddr *sa);

void
sigchld_handler (int s);

#endif//_UTILS_H_