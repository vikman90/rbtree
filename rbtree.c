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

static void rb_replace(rb_tree * tree, rb_node * node, rb_node * t) {
    if (node->parent == NULL) {
        tree->root = t;
    } else if (node == node->parent->left) {
        node->parent->left = t;
    } else {
        node->parent->right = t;
    }

    if (t) {
        t->parent = node->parent;
    }

    free(node->key);
    free(node);
}

static void rb_move(rb_node * node, rb_node * t) {
    free(node->key);
    node->key = t->key;
    node->value = t->value;

    // Subtree, assumming t is a minimum or maximum node (zero or one subtrees)
    rb_node * s = t->left ? t->left : t->right;

    if (t == t->parent->left) {
        t->parent->left = s;
    } else {
        t->parent->right = s;
    }

    if (s) {
        s->parent = t->parent;
    }

    free(t);
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

/*
static rb_node * rb_grandparent(rb_node * node) {
    return (node->parent != NULL) ? node->parent->parent : NULL;
}
*/

static rb_node * rb_uncle(rb_node * node) {
    rb_node * gp;
    return (node->parent && (gp = node->parent->parent)) ? (node->parent == gp->left) ? gp->right : gp->left : NULL;
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

/*
static void rb_balance_insert(rb_tree * tree, rb_node * node) {
    // fprintf(stderr, "rb_balance_insert(%s)\n", node->key);

    if (node->parent == NULL) {
        // Case 1
        // fprintf(stderr, "  (%s) <= BLACK\n", node->key);
        node->color = RB_BLACK;
    } else if (node->parent->color == RB_RED) {
        // Case 3
        rb_node * uncle = rb_uncle(node);
        rb_node * gp = rb_grandparent(node);

        if (uncle != NULL && uncle->color == RB_RED) {
            // fprintf(stderr, "  (%s) <= BLACK\n", node->parent->key);
            // fprintf(stderr, "  (%s) <= BLACK\n", uncle->key);
            // fprintf(stderr, "  (%s) <= RED\n", gp->key);

            node->parent->color = RB_BLACK;
            uncle->color = RB_BLACK;
            // Assuming gp ≠ NULL as node has an uncle
            gp->color = RB_RED;
            rb_balance_insert(tree, gp);
        } else {
            // Case 4
            // Assuming gp ≠ NULL as parent is red
            if (node == node->parent->right && node->parent == gp->left) {
                // fprintf(stderr, "  left(%s)\n", node->parent->key);
                rb_rotate_left(tree, node->parent);
                node = node->left;
            } else if (node == node->parent->left && node->parent == gp->right) {
                // fprintf(stderr, "  right(%s)\n", node->parent->key);
                rb_rotate_right(tree, node->parent);
                node = node->right;
            }

            // Case 5

            // fprintf(stderr, "  (%s) <= BLACK\n", node->parent->key);
            // fprintf(stderr, "  (%s) <= RED\n", gp->key);

            node->parent->color = RB_BLACK;
            gp->color = RB_RED;

            if (node == node->parent->left && node->parent == gp->left) {
                // fprintf(stderr, "  right(%s)\n", gp->key);
                rb_rotate_right(tree, gp);
            } else {
                // fprintf(stderr, "  left(%s)\n", gp->key);
                rb_rotate_left(tree, gp);
            }
        }
    }
}
*/

#define grandparent parent->parent

static void rb_balance_insert(rb_tree * tree, rb_node * node) {
    // fprintf(stderr, "rb_balance_insert(%s)\n", node->key);

    while (node->parent && node->parent->color == RB_RED) {
        // fprintf(stderr, "  [node = (%s), parent = (%s)]\n", node->key, node->parent->key);
        rb_node * uncle = rb_uncle(node);

        if (uncle && uncle->color == RB_RED) {
            // fprintf(stderr, "  (%s) <= BLACK\n", node->parent->key);
            // fprintf(stderr, "  (%s) <= BLACK\n", uncle->key);
            // fprintf(stderr, "  (%s) <= RED\n", node->grandparent->key);

            node->parent->color = RB_BLACK;
            uncle->color = RB_BLACK;
            node->grandparent->color = RB_RED;

            node = node->grandparent;
        } else {
            if (node->parent == node->grandparent->left) {
                if (node == node->parent->right) {
                    node = node->parent;
                    // fprintf(stderr, "  left(%s)\n", node->key);
                    rb_rotate_left(tree, node);
                }

                // fprintf(stderr, "  (%s) <= BLACK\n", node->parent->key);
                // fprintf(stderr, "  (%s) <= RED\n", node->grandparent->key);

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                // fprintf(stderr, "  right(%s)\n", node->grandparent->key);
                rb_rotate_right(tree, node->grandparent);
            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    // fprintf(stderr, "  right(%s)\n", node->key);
                    rb_rotate_right(tree, node);
                }

                // fprintf(stderr, "  (%s) <= BLACK\n", node->parent->key);
                // fprintf(stderr, "  (%s) <= RED\n", node->grandparent->key);

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                // fprintf(stderr, "  left(%s)\n", node->grandparent->key);
                rb_rotate_left(tree, node->grandparent);
            }
        }
    }

    // fprintf(stderr, "  -- end\n");
    tree->root->color = RB_BLACK;
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
    rb_node * t = rb_get(tree->root, key);

    if (t == NULL) {
        return NULL;
    }

    void * value = t->value;
    rb_color color = t->color;

    if (t->left == NULL) {
        // No subtrees, or right subtree only
        rb_replace(tree, t, t->right);
    } else if (t->right == NULL) {
        // Left subtree only
        rb_replace(tree, t, t->left);
    } else {
        rb_node * m = rb_min(t->right);
        rb_move(t, m);
    }

    // TODO: balance

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
        // printf("\n");
    }
}
