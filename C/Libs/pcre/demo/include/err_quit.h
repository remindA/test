#ifndef _ERR_QUIT_H_
#define _ERR_QUIT_H_
#include <stdlib.h>
#include <errno.h>
static inline void err_quit(const char *api)
{
    perror(api);
    exit(1);
}


#endif

