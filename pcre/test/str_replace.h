#ifndef _STR_REPLACE_H_
#define _STR_REPLACE_H_
/*
 * 这两个宏在Makefile中开启
#ifndef DEBUG
#define DEBUG
#endif
#ifndef NAMED_GROUP
#define NAMED_GROUP
#endif
*/
#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pcre2.h>
#include "list.h"
#include "safe_free.h"

typedef struct node_substr{
    struct list_head list;
    size_t index;
    //size_t line_index;
    size_t startoffset;
    char   *rplstr;
    size_t len_substr;
    char   substr[0];
}node_substr_t;

typedef void (*pad_rplstr_t)(node_substr_t *node, void *table, size_t len);
extern void pad_list_rplstr_malloc(struct list_head *head, pad_rplstr_t pad, void *table, size_t len);




extern pcre2_code *get_compile_code(PCRE2_SPTR pattern, uint32_t compile_options);

extern struct list_head *get_list_substring_pattern(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options);

extern struct list_head *get_list_substring_compiled_code(PCRE2_SPTR subject, pcre2_code *re);

extern void free_list_substring(struct list_head **head);

extern void free_list_substring_node(struct list_head *pos);

extern void print_list_substr_node(struct list_head *pos);


extern PCRE2_SPTR _replace_all_malloc(PCRE2_SPTR subject, struct list_head *head, const char *replace_str);
extern PCRE2_SPTR replace_all_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options, const char *replace_str);


extern PCRE2_SPTR replace_all_default_malloc(PCRE2_SPTR subject, struct list_head *head);
//extern PCRE2_SPTR replace_all_default_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern);

extern PCRE2_SPTR _replace_index_malloc(PCRE2_SPTR subject, struct list_head *head, size_t index, const char *replace_str);
extern PCRE2_SPTR replace_index_malloc(PCRE2_SPTR subject, PCRE2_SPTR pattern, uint32_t compile_options, size_t index, const char *replace_str);



#endif

