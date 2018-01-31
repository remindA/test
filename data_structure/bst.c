/*
 * =====================================================================================
 *
 *       Filename:  bst.c
 *
 *    Description:  binary sort tree
 *
 *        Version:  1.0
 *        Created:  2018年01月29日 21时20分26秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct _bit_node{
    int data;
    struct _bit_node *left;
    struct _bit_node *right;
}bit_node_t;


bst_node_t *bst_create_tree(int key) {
    bit_node_t *root = (bit_node_t *)malloc(sizeof(bit_node_t));
    if(NULL == root) {
        return root;
    }
    root->data = key;
    root->left = NULL;
    root->right = NULL;
    return root;
}

/*
 * 参数:
 *      root: 二叉树的根节点
 *      key : 查找节点值
 *      key_root: 匹配节点的根节点(当匹配到根节点时，key_root==root)
 *  return:
 *      NULL: 没有此节点
 *      not NULL: 节点的位置
 */
bit_node_t *bst_search(bit_node_t *root, int key, bit_node_t **key_root)
{
    if(root == NULL) {
        return NULL;
    }
    *key_root = NULL;
    bit_node_t *tmp = root;
    while(tmp) {
        if(key == tmp->data) {
            printf("find node = %d\n", key);
            break;
        }
        else if(key < tmp->data) {
            *key_root = tmp;
            tmp = tmp->left;
        }
        else {
            *key_root = tmp;
            tmp = tmp->right;
        }
    }
    printf("key_root = %p\n", *key_root);
    return tmp;
}




int bst_insert(bit_node_t *root, int key)
{
    if(root == NULL) {
        return -1;
    }
    bit_node_t *key_root = NULL;
    if(NULL != bst_search(root, key, &key_root)) {
        return 1;
    }
    printf("gonna insert new node = %d, key_root = %p\n", key, key_root);
    bit_node_t *node = (bit_node_t *)malloc(sizeof(bit_node_t));
    if(NULL == node) {
        perror("malloc()");
        return -1;
    }
    node->data  = key;
    node->left  = NULL;
    node->right = NULL;
    if(key < key_root->data) {
        key_root->left = node;
    }
    /* else means: key > key_root->data */
    else {
        key_root->right = node;
    }
    printf("insert new node %d ok\n", key);
    return 0;
}


int bst_delete(bit_node_t *root, int key)
{
    bit_node_t *key_root;
    bit_node_t *node = bst_search(root, key, &key_root);
    if(node == NULL) {
        return 0;
    }

    /* bst only has one node(root) */
    if(key_root == NULL)
    {
        free(root);
        return 0;
    }
    /* only left || (no left && no right) */
    if(node->right == NULL) {
        if(key_root->left == node) {
            key_root->left = node->left;
        }
        else {
            key_root->right = node->left;
        }
        free(node);
        return 0;
    }
    /* only right */
    else if(node->left == NULL) {
        if(key_root->left == node) {
            key_root->left = node->right;
        }
        else {
            key_root->right = node->right;
        }
        free(node);
        return 0;
    }
    /* both */
    else {
        /* 右子树的最左节点 */
        bit_node_t *tmp = node->left;
        while(tmp->left) tmp = tmp->left;
        node->data = tmp->data;
        free(tmp);
        return 0;
    } 
}

/* 遍历二叉树,并使用回调函数进行遍历操作 */
/*
void bt_traversal(bit_node_t *root, bt_traversal_cb *cd)
{

}
*/


/* 只有根节点的情况还没处理好 */
int main(int argc, char **argv)
{
    bit_node_t *root = (bit_node_t *)malloc(sizeof(bit_node_t));
    root->data = 1;
    root->left = NULL;
    root->right = NULL;
    bst_insert(root, 1);
    bst_insert(root, 2);
    bst_insert(root, 2);
    bst_insert(root, 3);
    bst_insert(root, 3);
    bst_insert(root, 4);
    bst_insert(root, 4);
    bst_insert(root, 5);
    bst_insert(root, 5);
    return 0;
}
