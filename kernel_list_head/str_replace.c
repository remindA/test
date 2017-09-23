/* 字符串替换 */

typedef struct node_substr
{
	struct list_head list;
	//size_t index;
	//size_t line_index;
	size_t startoffset;
	size_t endoffset;
	char   substr[0];
}node_substr_t;

PCRE2_SPTR replace_all(PCRE2_SPTR subject, PCRE2_SPTR *pattern, const char *str_replace)
{
	
	
}

/* 用于从subject中获取匹配串的信息，生成链表 */
struct list_head *get_sub_list(subject, pattern)
{
	pcre2_compile();
	
	//第一次pcre2_match()
	pcre2_match()
	
	struct list_head *head = (struct list_head *)malloc(sizeof(struct list_head));
	init_list_head(head);
	
	int len = vector[1] - vector[0];
	node_substr_t *node = (node_substr_t *)malloc(sizeof(node_substr_t) + len + 1);
	node->startoffset = vector[0];
	node->endoffset   = node->startoffset + len;
	strncpy(node->substr, subject + node->startoffset, len);
	list_add(&(node->list), head);
}

/* 通过生成的链表进行一系列操作
 * 替换指定的子串(index, line_index)
 * 替换所有子串

