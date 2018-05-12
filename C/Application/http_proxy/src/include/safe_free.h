#ifndef _SAFE_FREE_H_
#define _SAFE_FREE_H_
#include <stdio.h>
#include <stdlib.h>
#define SAFE_FREE(ptr) safe_free((void **)&ptr)

static inline void safe_free(void **ptr)
{
	if(NULL != ptr && NULL != *ptr)
	{
		free(*ptr);
		*ptr = NULL;
	}
}
#endif

