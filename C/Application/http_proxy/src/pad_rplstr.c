#include "pad_rplstr.h"


//typedef void (*pad_rplstr_t)(node_substr_t *node, struct list_head *head_table);
//这个函数将要取代上面的函数

/* 根据匹配字符串，找到替换字符串
 * @node: 存放匹配到的字符串及相关信息
 * @head_table: 映射表
 */
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


/* 根据匹配字符串，找到替换字符串
 * @node: 存放匹配到的字符串及相关信息
 * @head_table: 映射表
 */
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


/*
 * 根据匹配字符串，找到替换字符串
 * lan2wan把匹配串为中lan地址都替为wan地址
 * wan2lan把匹配串为中wan地址都替为lan地址
 * map_tab: 存放匹配串和替换串的表
 * @node: 存放匹配到的字符串及相关信息
 * @head: useless
 */
extern map_t *map_tab;
void pad_list_rplstr_lan2wan(node_substr_t *node, struct list_head *head)
{
    int i;
    ip_t *p;
    for(i=0, p = map_tab[_LAN].ip_tab; p->ip; i++, p++) {
		if (strcmp(node->substr, p->ip) == 0)
		{
            char *rpl = (map_tab[_WAN].ip_tab[i].ip);
//#ifdef PADDEBUG
			printf("node->substr=%s, match=%s, rpl=%s\n", node->substr, p->ip, rpl);
//#endif
			int len_rpl = strlen(rpl);
			node->rplstr = (char *) malloc(len_rpl + 1);
			if (NULL == node->rplstr)
			{
				perror("malloc");
			}
			else
			{
				memset(node->rplstr, 0, len_rpl + 1);
				memcpy(node->rplstr, rpl, len_rpl);
			}
            break;
		}
	}
}

void pad_list_rplstr_wan2lan(node_substr_t *node, struct list_head *head)
{
    int i;
    ip_t *p;
    for(i=0, p = map_tab[_WAN].ip_tab; p->ip; i++, p++) {
		if (strcmp(node->substr, p->ip) == 0)
		{
            char *rpl = (map_tab[_LAN].ip_tab[i].ip);
//#ifdef PADDEBUG
			printf("node->substr=%s, match=%s, rpl=%s\n", node->substr, p->ip, rpl);
//#endif
			int len_rpl = strlen(rpl);
			node->rplstr = (char *) malloc(len_rpl + 1);
			if (NULL == node->rplstr)
			{
				perror("malloc");
			}
			else
			{
				memset(node->rplstr, 0, len_rpl + 1);
				memcpy(node->rplstr, rpl, len_rpl);
			}
            break;
		}
	}
}

