#include "../../hdr/macros.h" // FAILURE
#include "../../hdr/error/utils.h"
#include <stdio.h> 		// perror()
#include <openssl/err.h>	// ERR_get_error()


/**
 * Always returns FAILURE
 * prints a message corresponding to the error
 */
int
general_error (
    char *error_msg)
{
    perror(error_msg);
    return FAILURE;
}

/**
 * Always returns FAILURE
 * prints a message corresponding to the
 * openssl error
 */
int
openssl_error (
    char *error_msg)
{
    unsigned long error_code = ERR_get_error();
    perror(error_msg);
    perror(ERR_error_string(error_code, NULL));
    return FAILURE;
}
