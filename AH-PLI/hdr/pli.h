#ifndef _PLI_H_
#define _PLI_H_

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>     // memset()
#include <sys/socket.h> // send()
#include <unistd.h>     // close()
#include "../hdr/utils.h"
#include "../hdr/elgamal-utils.h"
#include "../hdr/mh-elgamal.h"
#include "../hdr/ah-elgamal.h"

#define MAX_MSG_LEN 1024 // number of bytes in a message

enum HomomorphismType {
    AH, MH
};

int
server_run_pli (int                  new_fd,
		enum HomomorphismType htype);

int
client_run_pli (int                  sockfd,
		enum HomomorphismType htype);

#endif//_PLI_H_
