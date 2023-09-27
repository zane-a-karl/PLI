#ifndef _LOGGING_UTILS_H_
#define _LOGGING_UTILS_H_

#include <stdio.h>
#include <stdlib.h> // calloc()
#include <string.h> // strnlen()
#include <time.h>   // clock_gettime()


typedef struct LogItems {
    char *pmeth;
    char *eflav;
    char *htype;
} LogItems;

#define TSTART(sp)							\
    LogItems *l = parse_src_filename(__FILE__);				\
    logfile = calloc(32, sizeof(char));					\
    snprintf(logfile, 32, "%s%s-%s-%s-%lu.%s", "logs/", l->pmeth, l->eflav, l->htype, sp, "csv"); \
    free(l->pmeth);							\
    free(l->eflav);							\
    free(l->htype);							\
    free(l);								\
    logfs = fopen(logfile, "a");					\
    printf("Starting the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t1);

/* #define TSTART(sp)				\ */
/*     logfile = calloc(32, sizeof(char));		\ */
/*     logfs = stdout;				\ */
/*     printf("Starting the clock: \n");		\ */
/*     clock_gettime(CLOCK_MONOTONIC, &t1); */

#define TTICK clock_gettime(CLOCK_MONOTONIC, &t2);			\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs,"Line:%5d, Time = %f\n",__LINE__,sec);

#define COLLECT_LOG_ENTRY(secpar, n_entries, bytes)			\
    printf("Ending the clock: \n");					\
    clock_gettime(CLOCK_MONOTONIC, &t2);				\
    sec = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1000000000.0; \
    fprintf(logfs, "%lu, ", secpar);					\
    fprintf(logfs, "%d, ", n_entries);					\
    fprintf(logfs, "%" PRIu64 ", ", bytes);				\
    fprintf(logfs,"%f\n", sec);						\
    free(logfile);							\
    fclose(logfs);							

LogItems *
parse_src_filename (
    char *filename);

#endif//_LOGGING_UTILS_H_
