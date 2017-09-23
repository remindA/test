#ifndef _PAD_RPLSTR_H_
#define _PAD_RPLSTR_H_
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "str_replace.h"
#include "list.h"
#include "socket_tools.h"

#define REMAP_FILE "/tmp/nvram"
#define LEN_IP  16
#define LEN 12
typedef struct _remap
{
    char before[LEN_IP];
    char after[LEN_IP];
}remap_t;

typedef struct _remap_entry
{
    char before[LEN_IP];
    char after[LEN_IP];
    struct list_head list;
}remap_entry_t;

char *nvram_data;

extern void pad_remap_rplstr_malloc(node_substr_t *node, void *remap_tab, size_t len);
//extern void pad_remap_rplstr_malloc(node_substr_t *node, struct list_head *head_table);

extern void pad_remap_rplstr_m(node_substr_t *node, struct list_head *head_table);
extern struct list_head *get_remap_table_malloc(void);
extern void free_remap_table(struct list_head **head);

#endif

