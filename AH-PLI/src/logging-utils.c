#include "../hdr/logging-utils.h"


/**
 * This takes the filename from one of the protocol files
 * which all look like <pli method>-<elgamal flavor>-<homomorphism type>.c
 * So we split the filename by '-' and then set each section of the log items
 * @param filename of the protocol file
 */
LogItems *
parse_src_filename (
    char *filename)
{
    const int split_char = '-';
    const char *prefix = "src/protocols/";
    const char *suffix = ".c";
    int filename_len;
    int prefix_len;
    int name_len;
    int suffix_len;
    LogItems *items;
    char *name;

    /* Remove "src/protocols/" prefix  */
    prefix_len   = strnlen(prefix, MAX_FILENAME_LEN);
    if ( 0 == strncmp(filename, prefix, prefix_len) ) {
	filename = filename + prefix_len;
    }

    /* Deep copy the filename otherwise suffix truncation seg faults */
    /* Deep copy after prefix trucation because otherwise we need to
       save the original pointer to free correctly */
    filename_len = strnlen(filename, MAX_FILENAME_LEN);
    name = calloc(filename_len, sizeof(*name));
    for (int i = 0; i < filename_len; i++) {
	name[i] = filename[i];
    }

    /* Remove ".c" suffix  */
    name_len   = strnlen(name, MAX_FILENAME_LEN);
    suffix_len = strnlen(suffix, MAX_FILENAME_LEN);
    if ( 0 == strncmp(name + name_len - suffix_len, suffix, suffix_len) ) {
	for (int i = name_len - suffix_len; i < name_len; i++)
	    name[i] = '\0';
    }

    /* This is more than I need for each section but predictably so */
    items        = calloc(1, sizeof(LogItems));
    items->pmeth = calloc(name_len, sizeof(char));
    items->eflav = calloc(name_len, sizeof(char));
    items->htype = calloc(name_len, sizeof(char));
    /* Start at 1 because split array will  always have at least one element */
    for (int i = 0, split_i = 0, field = 0; i < name_len; i++) {
	for (int j = split_i; j < name_len; j++) {
	    if (name[j] == split_char) {
		split_i = j + 1;
		field += 1;
		break;
	    }
	    if (field == 0) {
		items->pmeth[j-split_i] = name[j];
	    } else if (field == 1) {
		items->eflav[j-split_i] = name[j];
	    } else if (field == 2) {
		items->htype[j-split_i] = name[j];
	    } else {
		break;
	    }
	}
    }

    free(name);
    return items;
}
