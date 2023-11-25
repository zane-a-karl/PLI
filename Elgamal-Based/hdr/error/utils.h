#ifndef ERROR_UTILS_H
#define ERROR_UTILS_H

/*******************Include Prerequisites******************
#include "../../hdr/macros.h" // SUCCESS
**********************************************************/

int
general_error (
    char *error_msg);

int
openssl_error (
    char *error_msg);

#endif//ERROR_UTILS_H
