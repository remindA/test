#ifndef _PAD_RPLSTR_H_
#define _PAD_RPLSTR_H_
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "config.h"
#include "str_replace.h"
#include "list.h"


extern void pad_list_rplstr_remap_table_req_m(node_substr_t *node, struct list_head *head_table);
extern void pad_list_rplstr_remap_table_rsp_m(node_substr_t *node, struct list_head *head_table);


#endif

