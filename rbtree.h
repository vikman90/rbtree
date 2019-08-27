/**
 * @file rbtree.h
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief RB tree data structure declaration
 * @version 0.1
 * @date 2019-08-21
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 *
 */

#ifndef RBTREE_H
#define RBTREE_H

/// Possible colors of a red-black tree
typedef enum rb_color { RB_RED, RB_BLACK } rb_color;

/// Red-black tree node
typedef struct rb_node {
    char * key;                 ///< Node key
    void * value;               ///< Pointer to value
    rb_color color;             ///< Node color
    struct rb_node * parent;    ///< Pointer to parent node
    struct rb_node * left;      ///< Pointer to left child
    struct rb_node * right;     ///< Pointer to right child
} rb_node;

/**
 * @brief Red-black tree abstract data type
 *
 * A red-black tree is a self-balanced binary search tree.
 *
 * It supports O(log n) insertion, deletion and search.
 */
typedef struct rb_tree {
    rb_node * root;             ///< Pointer to root node.
} rb_tree;

/**
 * @brief Create a red-black tree
 *
 * @return Pointer to an empty tree.
 */

rb_tree * rbtree_init();

/**
 * @brief Free a red-black tree
 * @post The tree is destroyed, including keys. Values are not freed.
 * @param tree Pointer to a red-black tree.
 */

void rbtree_destroy(rb_tree * tree);

/**
 * @brief Insert a key-value in the tree
 *
 * @param tree Pointer to a red-black tree.
 * @param key Data key, used for ordering.
 * @param value Data value.
 * @return Pointer to value, on success.
 * @retval NULL Key already exists in the tree.
 */

void * rbtree_insert(rb_tree * tree, const char * key, void * value);

/**
 * @brief Retrieve a value from the tree
 *
 * @param tree Pointer to a red-black tree.
 * @param key Data key (search criteria).
 * @return Pointer to data value, if found.
 * @retval NULL Key not found.
 */

void * rbtree_get(const rb_tree * tree, const char * key);

/**
 * @brief Remove a value from the tree
 *
 * @param tree Pointer to a red-black tree.
 * @param key Data key.
 * @return Pointer to value removed, on success.
 * @retval NULL Key not in the tree.
 */

void * rbtree_delete(rb_tree * tree, const char * key);

/**
 * @brief Get the minimum key in the tree
 *
 * @param tree Pointer to a red-black tree.
 * @return Minimum key in the tree.
 * @retval NULL The tree is empty.
 */

const char * rbtree_minimum(const rb_tree * tree);

/**
 * @brief Get the maximum key in the tree
 *
 * @param tree Pointer to a red-black tree.
 * @return Maximum key in the tree.
 * @retval NULL The tree is empty.
 */

const char * rbtree_maximum(const rb_tree * tree);

/**
 * @brief Get all the keys in the tree
 *
 * Retrieve all the keys, ordered alphabetically (inorder traversal).
 *
 * @param tree
 * @return Null-terminated array of keys.
 */

char ** rbtree_keys(const rb_tree * tree);

/**
 * @brief Get all the keys from the tree within a range
 *
 * Retrieve all the keys in the closed range [min, max], ordered alphabetically
 * (inorder traversal).
 *
 * @param tree Pointer to a red-black tree.
 * @param min Minimum key.
 * @param max Maximum key.
 * @return Null-terminated array of keys.
 */

char ** rbtree_range(const rb_tree * tree, const char * min, const char * max);

/**
 * @brief Get the black depth of a tree
 *
 * The black depth of a red-black tree is the number of black nodes from the
 * root to any leaf, including null leafs (that are black).
 *
 * This function is test-oriented.
 *
 * @param tree Pointer to a red-black tree.
 * @return Number of black nodes from the root.
 * @retval -1 The tree is unbalanced. This would mean a bug.
 */

int rbtree_black_depth(const rb_tree * tree);

/**
 * @brief Get the size of the tree
 *
 * @param tree Pointer to a red-black tree.
 * @return unsigned Number of elements in the tree.
 */

unsigned rbtree_size(const rb_tree * tree);

/**
 * @brief Check whether the tree is empty.
 *
 * @param tree Pointer to a red-black tree.
 * @retval 1 The tree is empty.
 * @retval 0 The tree is not empty.
 */
int rbtree_empty(const rb_tree * tree);

#endif
