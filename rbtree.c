/**
 * @file rbtree.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief RB tree data structure definition
 * @version 0.1
 * @date 2019-08-21
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rbtree.h"

/* Private functions **********************************************************/

#define grandparent parent->parent

/**
 * @brief Create and initialize a red-black tree node
 *
 * @param key Data key. It will be duplicated.
 * @param value Data value.
 * @return Pointer to a newly created node.
 */

static rb_node * rb_init(const char * key, void * value) {
    rb_node * node = calloc(1, sizeof(rb_node));
    node->key = strdup(key);
    node->value = value;
    node->color = RB_RED;
    return node;
}

/**
 * @brief Free a red-black subtree
 * @post The subtree is destroyed, including keys. Values are not freed.
 * @param node Pointer to a red-black tree node.
 */

static void rb_destroy(rb_node * node) {
    if (node->left) {
        rb_destroy(node->left);
    }

    if (node->right) {
        rb_destroy(node->right);
    }

    free(node->key);
    free(node);
}

/**
 * @brief Find a node from a subtree
 *
 * @param node Pointer to a red-black tree node.
 * @param key Data key (search criteria).
 * @return Pointer to the node storing the key, if found.
 * @retval NULL Key not found.
 */

rb_node * rb_get(rb_node * node, const char * key) {
    while (node != NULL) {
        int cmp = strcmp(key, node->key);

        if (cmp == 0) {
            break;
        }

        node = cmp < 0 ? node->left : node->right;
    }

    return node;
}

/**
 * @brief Get the node with the minimum key from a subtree
 *
 * Return the leftmost node of the subtree.
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the node storing the minimum key.
 */

static rb_node * rb_min(rb_node * node) {
    rb_node * t;
    for (t = node; t->left != NULL; t = t->left);
    return t;
}

/**
 * @brief Get the node with the maximum key from a subtree
 *
 * Return the rightmost node of the subtree.
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the node storing the maximum key.
 */

static rb_node * rb_max(rb_node * node) {
    rb_node * t;
    for (t = node; t->right != NULL; t = t->right);
    return t;
}

/**
 * @brief Get the uncle of a node
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the sibling of node's parent.
 */

static rb_node * rb_uncle(rb_node * node) {
    rb_node * gp;
    return (node->parent && (gp = node->grandparent)) ? (node->parent == gp->left) ? gp->right : gp->left : NULL;
}

/**
 * @brief Rotate a subtree to left
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the pivot node.
 */

static void rb_rotate_left(rb_tree * tree, rb_node * node) {
    rb_node * t = node->right;

    if (node->parent == NULL) {
        tree->root = t;
    } else {
        if (node == node->parent->left) {
            node->parent->left = t;
        } else {
            node->parent->right = t;
        }
    }

    if (t->left) {
        t->left->parent = node;
    }

    node->right = t->left;
    t->left = node;
    t->parent = node->parent;
    node->parent = t;
}

/**
 * @brief Rotate a subtree to right
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the pivot node.
 */

static void rb_rotate_right(rb_tree * tree, rb_node * node) {
    rb_node * t = node->left;

    if (node->parent == NULL) {
        tree->root = t;
    } else {
        if (node == node->parent->left) {
            node->parent->left = t;
        } else {
            node->parent->right = t;
        }
    }

    if (t->right) {
        t->right->parent = node;
    }

    node->left = t->right;
    t->right = node;
    t->parent = node->parent;
    node->parent = t;
}

/**
 * @brief Balance a tree after an insertion
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the node that was inserted.
 */

static void rb_balance_insert(rb_tree * tree, rb_node * node) {
    while (node->parent && node->parent->color == RB_RED) {
        rb_node * uncle = rb_uncle(node);

        if (uncle && uncle->color == RB_RED) {
            node->parent->color = RB_BLACK;
            uncle->color = RB_BLACK;
            node->grandparent->color = RB_RED;

            node = node->grandparent;
        } else {
            if (node->parent == node->grandparent->left) {
                if (node == node->parent->right) {
                    node = node->parent;
                    rb_rotate_left(tree, node);
                }

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                rb_rotate_right(tree, node->grandparent);
            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    rb_rotate_right(tree, node);
                }

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                rb_rotate_left(tree, node->grandparent);
            }
        }
    }

    tree->root->color = RB_BLACK;
}

/**
 * @brief Balance a tree after a deletion
 *
 * @param tree Pointer to the red-black tree.
 * @param node Pointer to the node that was deleted.
 * @param parent Pointer to the parent of node.
 */

static void rb_balance_delete(rb_tree * tree, rb_node * node, rb_node * parent) {
    while (parent != NULL && (node == NULL || node->color == RB_BLACK)) {
        if (node == parent->left) {
            rb_node * sibling = parent->right;

            if (sibling->color == RB_RED) {
                // Case 1: sibling is red

                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_left(tree, parent);
                sibling = parent->right;
            }

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Case 2: sibling is black and both nephews are black

                sibling->color = RB_RED;
                node = parent;
                parent = parent->parent;

            } else {
                if (!sibling->right || sibling->right->color == RB_BLACK) {
                    // Case 3: Sibling is black, left nephew is red and right nephew is black

                    sibling->left->color = RB_BLACK;
                    sibling->color = RB_RED;
                    rb_rotate_right(tree, sibling);
                    sibling = parent->right;
                }

                // Case 4: Sibling is black, right nephew is red

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->right->color = RB_BLACK;
                rb_rotate_left(tree, parent);

                break;
            }
        } else {
            rb_node * sibling = parent->left;

            if (sibling->color == RB_RED) {
                // Case 1b: sibling is red

                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_right(tree, parent);
                sibling = parent->left;
            }

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Case 2b: sibling is black and both nephews are black

                sibling->color = RB_RED;
                node = parent;
                parent = parent->parent;
            } else {
                if (!sibling->left || sibling->left->color == RB_BLACK) {
                    // Case 3b: Sibling is black, left nephew is red and right nephew is black

                    sibling->right->color = RB_BLACK;
                    sibling->color = RB_RED;
                    rb_rotate_left(tree, sibling);
                    sibling = parent->left;
                }

                // Case 4b: Sibling is black, right nephew is red

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->left->color = RB_BLACK;
                rb_rotate_right(tree, parent);

                break;
            }
        }
    }

    if (node) {
        node->color = RB_BLACK;
    }
}

/**
 * @brief Get all the keys in a subtree
 *
 * @param node Pointer to a red-black tree node.
 * @param array Pointer to the target string array.
 * @param size[in,out] Pointer to the current size of the array.
 * @pre array is expected to be size cells long.
 * @post array is reallocated to size+2 cells long.
 * @post array is no longer valid after calling this function.
 * @return Newly allocated null-terminated array of keys.
 */

static char ** rb_keys(rb_node * node, char ** array, unsigned * size) {
    if (node->left) {
        array = rb_keys(node->left, array, size);
    }

    array = realloc(array, sizeof(char *) * (*size + 2));
    array[(*size)++] = strdup(node->key);

    if (node->right) {
        array = rb_keys(node->right, array, size);
    }

    return array;
}

/**
 * @brief Get all the keys from the subtree within a range
 *
 * @param node Pointer to a red-black tree node.
 * @param min Minimum key.
 * @param max Maximum key.
 * @param array Pointer to the target string array.
 * @param size[in,out] Pointer to the current size of the array.
 * @pre array is expected to be size cells long.
 * @post array is reallocated to size+2 cells long.
 * @post array is no longer valid after calling this function.
 * @return Newly allocated null-terminated array of keys.
 */

static char ** rb_range(rb_node * node, const char * min, const char * max, char ** array, unsigned * size) {
    int cmp_min = strcmp(node->key, min);
    int cmp_max = strcmp(node->key, max);

    if (node->left && cmp_min > 0) {
        // node > min
        array = rb_range(node->left, min, max, array, size);
    }

    if (cmp_min >= 0 && cmp_max <= 0) {
        // min <= node <= max
        array = realloc(array, sizeof(char *) * (*size + 2));
        array[(*size)++] = strdup(node->key);
    }

    if (node->right && cmp_max < 0) {
        // node < min
        array = rb_range(node->right, min, max, array, size);
    }

    return array;
}

/**
 * @brief Get the black depth of a red-black subtree
 *
 * The black depth of a node is the number of black nodes from it to any leaf,
 * including null leafs (that are black) and excluding the node itself.
 *
 * This function is test-oriented: it checks that all possible paths from the
 * root to every leaf matches, and returns the length of this path.
 *
 * @param node Pointer to a red-black tree node.
 * @return Number of black nodes from this node.
 * @retval -1 The subtree is unbalanced. This would mean a bug.
 */

static int rb_black_depth(rb_node * node) {
    if (node == NULL) {
        return 1;
    }

    int d_left = rb_black_depth(node->left);
    int d_right = rb_black_depth(node->right);

    if (d_left != d_right) {
        return -1;
    }

    return d_left + (node->color == RB_BLACK);
}

/**
 * @brief Get the size of a subtree
 *
 * This function is recursive: 1 + rb_size(left subtree) + rb_size(right subtree).
 *
 * @param node Pointer to a red-black tree node.
 * @return Number of nodes in the subtree.
 */

unsigned rb_size(rb_node * node) {
    return (node->left ? rb_size(node->left) : 0) + 1 + (node->right ? rb_size(node->right) : 0);
}

/* Public functions ***********************************************************/

// Create a red-black tree

rb_tree * rbtree_init() {
    return calloc(1, sizeof(rb_tree));
}

// Free a red-black tree

void rbtree_destroy(rb_tree * tree) {
    if (tree->root) {
        rb_destroy(tree->root);
    }

    free(tree);
}

// Insert a key-value in the tree

void * rbtree_insert(rb_tree * tree, const char * key, void * value) {
    rb_node * node = rb_init(key, value);
    rb_node * parent = NULL;
    int cmp;

    for (rb_node * t = tree->root; t != NULL; t = cmp < 0 ? t->left : t->right) {
        parent = t;
        cmp = strcmp(key, t->key);

        if (cmp == 0) {
            // Duplicate key
            rb_destroy(node);
            return NULL;
        }
    }

    if (parent == NULL) {
        tree->root = node;
    } else if (cmp < 0) {
        parent->left = node;
    } else {
        parent->right = node;
    }

    node->parent = parent;
    rb_balance_insert(tree, node);

    return value;
}
// Retrieve a value from the tree

void * rbtree_get(const rb_tree * tree, const char * key) {
    rb_node * node = rb_get(tree->root, key);
    return node ? node->value : NULL;
}

// Remove a value from the tree

void * rbtree_delete(rb_tree * tree, const char * key) {
    rb_node * node = rb_get(tree->root, key);

    if (node == NULL) {
        return NULL;
    }

    // Succesor: node that will be actually deleted
    rb_node * s = (node->left && node->right) ? rb_min(node->right) : node;
    rb_node * t = (s->left) ? s->left : s->right;

    if (s->parent == NULL) {
        tree->root = t;
    } else if (s == s->parent->left) {
        s->parent->left = t;
    } else {
        s->parent->right = t;
    }

    if (t) {
        t->parent = s->parent;
    }

    if (node != s) {
        // Copy successor into node
        free(node->key);
        node->key = s->key;
        node->value = s->value;
        s->key = NULL;
    }

    if (s->color == RB_BLACK) {
        rb_balance_delete(tree, t, s->parent);
    }

    void * value = s->value;

    free(s->key);
    free(s);

    return value;
}

// Get the minimum key in the tree

const char * rbtree_minimum(const rb_tree * tree) {
    return tree->root ? rb_min(tree->root)->key : NULL;
}

// Get the maximum key in the tree

const char * rbtree_maximum(const rb_tree * tree) {
    return tree->root ? rb_max(tree->root)->key : NULL;
}

// Get all the keys in the tree

char ** rbtree_keys(const rb_tree * tree) {
    unsigned size = 0;
    char ** array = malloc(sizeof(char *));

    if (tree->root) {
        array = rb_keys(tree->root, array, &size);
    }

    array[size] = NULL;
    return array;
}

// Get all the keys from the tree within a range

char ** rbtree_range(const rb_tree * tree, const char * min, const char * max) {
    unsigned size = 0;
    char ** array = malloc(sizeof(char *));

    if (tree->root) {
        array = rb_range(tree->root, min, max, array, &size);
    }

    array[size] = NULL;
    return array;
}

// Get the black depth of a tree

int rbtree_black_depth(const rb_tree * tree) {
    if (tree->root == NULL) {
        return 0;
    }

    if (tree->root->color == RB_RED) {
        return -1;
    }

    int d_left = rb_black_depth(tree->root->left);
    int d_right = rb_black_depth(tree->root->right);

    return (d_left == -1 || d_right == -1 || d_left != d_right) ? -1 : d_left;
}

// Get the size of the tree

unsigned rbtree_size(const rb_tree * tree) {
    return tree->root ? rb_size(tree->root) : 0;
}

// Check whether the tree is empty

int rbtree_empty(const rb_tree * tree) {
    return tree->root == NULL;
}
