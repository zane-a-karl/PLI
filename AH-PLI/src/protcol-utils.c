#include "../hdr/protocol-utils.h"

int
run (
    Protocol pli_method,
    int              fd,
    int         sec_par,
    char      *filename)
{
    int r = pli_method(fd, sec_par, filename);
    if (!r) { return general_error("Failed during execution of run()"); }
    return SUCCESS;
}