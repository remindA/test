/*
 * =====================================================================================
 *
 *       Filename:  bst.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年07月26日 19时30分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
/*
 * 递归函数使用xxx_r结尾
 */


struct bst {
    uint32_t key;
    struct bst *parent;
    struct bst *left;
    struct bst *right;
};

typedef struct bst bst_node_t;

typedef struct {
    bst_node_t node;
    int data;
}data_t;


/* 创建节点 */
bst_node_t *bst_create_node(uint32_t key, bst_node_t *parent, bst_node_t *left, bst_node_t *right)
{
    bst_node_t *node = (bst_node_t *)calloc(1, sizeof(*node));
    if(NULL == node) {
        perror("calloc()");
        return NULL;
    }
    node->key = key;
    node->left = left;
    node->right = right;
    return node;
}

bst_node_t *bst_create_root()
{
    return bst_create_node(1<<16, NULL, NULL, NULL);
}

/*
 * 递归遍历
 */
void bst_pre_foreach_r(bst_node_t *root)
{
    if(root) {
        bst_pre_foreach(root->left);
        printf("%d\n", root->key);
        bst_pre_foreach(root->right);
    }
}

void bst_mid_foreach_r(bst_node_t *root)
{
    if(root) {
        printf("%d\n", root->key);
        bst_mid_foreach(root->left);
        bst_mid_foreach(root0>right);
    }
}

void bst_post_foreach_r(bst_node_t *root)
{
    if(root) {
        bst_post_foreach(root->left);
        bst_post_foreach(root->right);
        printf("%d\n", root->key);
    }
}

/* 递归查找 */
bst_node_t *bst_search_r(uint32_t key, bst_node_t *root)
{
    if(NULL == root || key == root->key) {
        return root;
    }
    if(key > root->key) {
        return bst_search2(key, root->right);
    }
    else {
        return bst_search2(key, root->left);
    }
}


bst_node_t *bst_search(uint32_t key, bst_node_t *root)
{
    bst_node_t *node = root;
    while(node && key != node->key) {
        if(key > node->key) {
            node = node->right;
        }
        else {
            node = node->left;
        }
    }
    return node;
}

/* BST中不允许有相同的key */
int bst_insert(bst_node_t *root, bst_node_t *node)
{
    /*
     * 确定位置
     */
    bst_node_t *parent;
    bst_node_t *tmp = root;
    while(node) {
        parent = node;
        if(node->key < tmp->key) {
            tmp = tmp->left;
        }
        else {
            tmp = tmp->right;
        }
    }
    node->parent = parent;
}

bst_node_t *bst_max(bst_node_t *root)
{
    bst_node_t *tmp = root;
    while(tmp && tmp->right) {
        tmp = tmp->right;
    }
    return tmp;
}

bst_node_t *bst_min(bst_node_t *root)
{
    bst_node_t *tmp = root;
    while(tmp && tmp->left) {
        tmp = tmp->left;
    }
    return tmp;
}

/*
 * 必须要明确两个概念
 * 节点的前驱:节点做左子数的最大节点, 前驱节点肯定只有左子树
 * 节点的后继:节点右子树的最小节点,　后继接点肯定只有右子树
 */
bst_node_t *bst_node_predecessor(bst_node_t *node)
{
    return bst_max(node->left);
}

bst_node_t *bst_node_successor(bst_node_t *node)
{
    return bst_min(node->right);
}


/* 
 * bst的删除稍微复杂些
 * 删除之后依然要保持bst的特征
 * 0. no left or right
 * 1. only has left
 * 2. only has right
 * 2. both left and right
 */
int bst_delete(bst_node_t *node)
{
    bst_node_t *parent = node->parent;
    if(NULL == node->left && NULL == node->right) {
        if(parent->left == node) {
            parent->left = NULL;
        }
        else {
            parent->right = NULL;
        }
    }
    else if(node->left && NULL == node->right) {
        if(parent->left == node) {
            parent->left = node->left;
        }
        else {
            parent->right = node->left;
        }
    }
    else if(node->right && NULL == node->left) {
        if(parent->left == node) {
            parent->left = node->right;
        }
        else {
            parent->right = node->right;
        }
    }
    else {
        /* 使用节点的前驱后或者后继来替代node
         * 然后处理下前驱或者后继的子树来替代前驱或者后继
         * 这里使用前驱来替代要删除的节点 
         * 如何替代:把前驱的数据域复制到node节点处,然后删除前驱接点(only left)
         */
    }
}

int bst_node_copy(bst_node_t *dst, bst_node_t *src)
{
    dst->key = src->key; 
}


