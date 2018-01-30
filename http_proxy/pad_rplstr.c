#include "pad_rplstr.h"



//typedef void (*pad_rplstr_t)(node_substr_t *node, void *table, size_t len);
/*
 * void pad_remap_rplstr_malloc(node_substr_t *node, void *remap_tab, size_t len)
 * {
 *  remap_t *remap_table = (remap_t *)remap_tab;
 *  int i = 0;
 *  for(i = 0; i < len; i++)
 *  {
 *      if(*(remap_table[i].before) != 0 && (strncmp(node->substr, remap_table[i].before, node->len_substr) == 0))
 *      {
 *          int len_rplstr = strlen(remap_table[i].after);
 *          node->rplstr = (char *)malloc(len_rplstr + 1);
 *          if(NULL == node->rplstr)
 *              perror("malloc node->rplstr");
 *          else
 *          {
 *              memset(node->rplstr, 0, len_rplstr + 1);
 *              memcpy(node->rplstr, remap_table[i].after, len_rplstr);
 *          }
 *      }
 *  }
 * }
 */

//typedef void (*pad_rplstr_t)(node_substr_t *node, struct list_head *head_table);
//这个函数将要取代上面的函数
void pad_list_rplstr_remap_table_req_m(node_substr_t *node, struct list_head *head_table)
{
	struct list_head *pos;

	list_for_each(pos, head_table){
		remap_entry_t *entry = list_entry(pos, remap_entry_t, list);

		if (strcmp(node->substr, entry->after) == 0)
		{
#ifdef PADDEBUG
			printf("node->substr=%s, entry->before=%s\n", node->substr, entry->after);
#endif
			int len_rpl = strlen(entry->before);
			node->rplstr = (char *) malloc(len_rpl + 1);
			if (NULL == node->rplstr)
			{
				perror("malloc");
			}
			else
			{
				memset(node->rplstr, 0, len_rpl + 1);
				memcpy(node->rplstr, entry->before, len_rpl);
			}
		}
	}
}

void pad_list_rplstr_remap_table_rsp_m(node_substr_t *node, struct list_head *head_table)
{
	struct list_head *pos;

	list_for_each(pos, head_table){
		remap_entry_t *entry = list_entry(pos, remap_entry_t, list);

		if (strcmp(node->substr, entry->before) == 0)
		{
#ifdef PADDEBUG
			printf("node->substr=%s, entry->before=%s\n", node->substr, entry->before);
#endif
			int len_rpl = strlen(entry->after);
			node->rplstr = (char *) malloc(len_rpl + 1);
			if (NULL == node->rplstr)
			{
				perror("malloc");
			}
			else
			{
				memset(node->rplstr, 0, len_rpl + 1);
				memcpy(node->rplstr, entry->after, len_rpl);
			}
		}
	}
}



