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

static rb_node * rb_init(const char * key, void * value) {
    rb_node * node = calloc(1, sizeof(rb_node));
    node->key = strdup(key);
    node->value = value;
    node->color = RB_RED;
    return node;
}

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

static rb_node * rb_min(rb_node * node) {
    rb_node * t;
    for (t = node; t->left != NULL; t = t->left);
    return t;
}

static rb_node * rb_max(rb_node * node) {
    rb_node * t;
    for (t = node; t->right != NULL; t = t->right);
    return t;
}

static rb_node * rb_uncle(rb_node * node) {
    rb_node * gp;
    return (node->parent && (gp = node->grandparent)) ? (node->parent == gp->left) ? gp->right : gp->left : NULL;
}

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

static void rb_print_keys(rb_node * node) {
    if (node->left) {
        rb_print_keys(node->left);
    }

    printf("%s\n", node->key);

    if (node->right) {
        rb_print_keys(node->right);
    }
}

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

unsigned rb_size(rb_node * node) {
    return (node->left ? rb_size(node->left) : 0) + 1 + (node->right ? rb_size(node->right) : 0);
}

/* Public functions ***********************************************************/

rb_tree * rbtree_init() {
    return calloc(1, sizeof(rb_tree));
}

void rbtree_destroy(rb_tree * tree) {
    if (tree->root) {
        rb_destroy(tree->root);
    }

    free(tree);
}

int rbtree_insert(rb_tree * tree, const char * key, void * value) {
    rb_node * node = rb_init(key, value);
    rb_node * parent = NULL;
    int cmp;

    for (rb_node * t = tree->root; t != NULL; t = cmp < 0 ? t->left : t->right) {
        parent = t;
        cmp = strcmp(key, t->key);

        if (cmp == 0) {
            // Duplicate key
            rb_destroy(node);
            return -1;
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
    return 0;
}

void * rbtree_get(rb_tree * tree, const char * key) {
    rb_node * node = rb_get(tree->root, key);
    return node ? node->value : NULL;
}

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

void * rbtree_minimum(rb_tree * tree) {
    return tree->root ? rb_min(tree->root) : NULL;
}

void * rbtree_maximum(rb_tree * tree) {
    return tree->root ? rb_max(tree->root) : NULL;
}

void rbtree_print_keys(rb_tree * tree) {
    if (tree->root) {
        rb_print_keys(tree->root);
    }
}

int rbtree_black_depth(rb_tree * tree) {
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

unsigned rbtree_size(rb_tree * tree) {
    return tree->root ? rb_size(tree->root) : 0;
}
