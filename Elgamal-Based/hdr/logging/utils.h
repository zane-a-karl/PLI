#ifndef LOGGING_UTILS_H
#define LOGGING_UTILS_H

/*******************Include Prerequisites******************
#include "../../hdr/macros.h" // MAX_FILENAME_LEN
**********************************************************/

typedef struct LogItems {
    char *pmeth;
    char *eflav;
    char *htype;
} LogItems;

#define TSTART(sp)							\
    LogItems *l = parse_src_filename(__FILE__);				\
    logfile = calloc(MAX_FILENAME_LEN, sizeof(char));			\
    snprintf(logfile, MAX_FILENAME_LEN, "%s%s-%s-%s-%lu.%s", "logs/",	\
	     l->pmeth, l->eflav, l->htype, sp, "csv");			\
    free(l->pmeth);							\
    free(l->eflav);							\
    free(l->htype);							\
    free(l);								\
    logfs = fopen(logfile, "a");					\
    printf("Starting the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t1);

/* #define TSTART(sp)				\ */
/*     logfile = calloc(MAX_FILENAME_LEN, sizeof(char));	\ */
/*     logfs = stdout;				\ */
/*     printf("Starting the clock: \n");		\ */
/*     clock_gettime(CLOCK_MONOTONIC, &t1); */

#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2);			\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs,"Line:%5d, Time = %f\n",__LINE__,sec);

#define COLLECT_LOG_ENTRY(secpar, list_len, thresh, matches, bytes)	\
    printf("Ending the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t2);				\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs, "%lu, ", secpar);					\
    fprintf(logfs, "%lu, ", list_len);					\
    fprintf(logfs, "%lu, ", thresh);					\
    fprintf(logfs, "%lu, ", matches);					\
    fprintf(logfs, "%" PRIu64 ", ", bytes);				\
    fprintf(logfs,"%f\n", sec);						\
    free(logfile);							\
    fclose(logfs);

LogItems *
parse_src_filename (
    char *filename);

#endif//LOGGING_UTILS_H
