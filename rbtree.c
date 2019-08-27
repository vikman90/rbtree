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
#include <assert.h>
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

/*
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
}

static void rb_move(rb_node * node, rb_node * t) {
    free(node->key);
    node->key = t->key;
    node->value = t->value;
    t->key = NULL;

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
}
*/

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

// static rb_node * rb_sibling(rb_node * node) {
//     return (node->parent) ? (node == node->parent->left) ? node->parent->right : node->parent->left : NULL;
// }

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

static void rb_balance_delete(rb_tree * tree, rb_node * node, rb_node * parent) {
    fprintf(stderr, "  rb_balance_delete( x = '%s', p = '%s' )\n", node ? node->key : "null", parent ? parent->key : "null");

    while (parent != NULL && (node == NULL || node->color == RB_BLACK)) {
        fprintf(stderr, "    it ( x = '%s', p = '%s' [%s] )\n", node ? node->key : "null", parent ? parent->key : "null", parent ? parent->color == RB_BLACK ? "black" : "red" : "");

        if (node == parent->left) {
            rb_node * sibling = parent->right;

            assert(sibling);

            if (sibling->color == RB_RED) {
                // Caso 1: fratello è rosso
                fprintf(stderr, "    -- case 1\n");
                fprintf(stderr, "    sibling = %s [%s]\n", sibling->key, sibling->color == RB_BLACK ? "black" : "red");

                fprintf(stderr, "    (%s) <= BLACK\n", sibling->key);
                fprintf(stderr, "    (%s) <= RED\n", parent->key);

                sibling->color = RB_BLACK;
                parent->color = RB_RED;

                fprintf(stderr, "    RLeft(%s)\n", parent->key);

                rb_rotate_left(tree, parent);
                sibling = parent->right;
            }

            assert(sibling);
            fprintf(stderr, "    sibling = %s [%s]\n", sibling->key, sibling->color == RB_BLACK ? "black" : "red");

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Caso 2: fratello è nero ed entrambi i nipoti sono neri
                fprintf(stderr, "    -- case 2\n");
                fprintf(stderr, "    (%s) <= RED\n", sibling->key);

                sibling->color = RB_RED;

                fprintf(stderr, "    node = (%s)\n", node ? node->key : "null");
                fprintf(stderr, "    parent = (%s)\n", parent ? parent->key : "null");

                node = parent;
                parent = parent->parent;

                fprintf(stderr, "    node <= (%s)\n", node ? node->key : "null");
                fprintf(stderr, "    parent <= (%s)\n", parent ? parent->key : "null");
            } else {
                if (!sibling->right || sibling->right->color == RB_BLACK) {
                    // Caso 3: Fratello è nero, nipote sinistro è rosso e nipote destro è nero
                    fprintf(stderr, "    -- case 3\n");

                    fprintf(stderr, "    (%s) <= BLACK\n", sibling->left->key);
                    fprintf(stderr, "    (%s) <= RED\n", sibling->key);
                    sibling->left->color = RB_BLACK;
                    sibling->color = RB_RED;
                    fprintf(stderr, "    RRight(%s)\n", parent->key);
                    rb_rotate_right(tree, sibling);
                    sibling = parent->right;
                }

                // Caso 4: Fratello è nero, nipote destro è rosso
                fprintf(stderr, "    -- case 4\n");

                fprintf(stderr, "    (%s) <= %s\n", sibling->key, parent->color == RB_BLACK ? "BLACK (copy)" : "RED (copy)");
                fprintf(stderr, "    (%s) <= BLACK\n", parent->key);
                fprintf(stderr, "    (%s) <= BLACK\n", sibling->right->key);

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->right->color = RB_BLACK;
                fprintf(stderr, "    RRight(%s)\n", parent->key);
                rb_rotate_left(tree, parent);
                break;
            }
        } else {
            rb_node * sibling = parent->left;

            assert(sibling);

            if (sibling->color == RB_RED) {
                // Caso 1: fratello è rosso
                fprintf(stderr, "    -- case 1b\n");

                fprintf(stderr, "    (%s) <= BLACK\n", sibling->key);
                fprintf(stderr, "    (%s) <= RED\n", parent->key);

                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_right(tree, parent);
                sibling = parent->left;
            }

            assert(sibling);

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Caso 2: fratello è nero ed entrambi i nipoti sono neri
                fprintf(stderr, "    -- case 2b\n");
                fprintf(stderr, "    (%s) <= RED\n", sibling->key);

                sibling->color = RB_RED;

                fprintf(stderr, "    node = (%s)\n", node ? node->key : "null");
                fprintf(stderr, "    parent = (%s)\n", parent ? parent->key : "null");

                node = parent;
                parent = parent->parent;

                fprintf(stderr, "    node <= (%s)\n", node ? node->key : "null");
                fprintf(stderr, "    parent <= (%s)\n", parent ? parent->key : "null");
            } else {
                if (!sibling->left || sibling->left->color == RB_BLACK) {
                    // Caso 3: Fratello è nero, nipote sinistro è rosso e nipote destro è nero
                    fprintf(stderr, "    -- case 3b\n");

                    fprintf(stderr, "    (%s) <= BLACK\n", sibling->right->key);
                    fprintf(stderr, "    (%s) <= RED\n", sibling->key);

                    sibling->right->color = RB_BLACK;
                    sibling->color = RB_RED;
                    fprintf(stderr, "    RLeft(%s)\n", parent->key);

                    rb_rotate_left(tree, sibling);
                    sibling = parent->left;
                }

                // Caso 4: Fratello è nero, nipote destro è rosso
                fprintf(stderr, "    -- case 4b\n");

                fprintf(stderr, "    (%s) <= %s\n", sibling->key, parent->color == RB_BLACK ? "BLACK (copy)" : "RED (copy)");
                fprintf(stderr, "    (%s) <= BLACK\n", parent->key);
                fprintf(stderr, "    (%s) <= BLACK\n", sibling->left->key);

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->left->color = RB_BLACK;
                fprintf(stderr, "    RLeft(%s)\n", parent->key);
                rb_rotate_right(tree, parent);
                break;
            }
        }
    }

    fprintf(stderr, "    -- end\n");

    if (node) {
        fprintf(stderr, "    (%s) <= BLACK\n", node->key);
        node->color = RB_BLACK;
    }
}

static void rb_print_keys(rb_node * node) {
    if (node->left) {
        rb_print_keys(node->left);
    }

    printf("%s [%s] [L=%s P=%s R=%s]\n", node->key, node->color == RB_BLACK ? "black" : "red", node->left ? node->left->key : "", node->parent ? node->parent->key : "ROOT", node->right ? node->right->key : "");

    if (node->right) {
        rb_print_keys(node->right);
    }
}

static int rb_depth(rb_node * node) {
    if (node == NULL) {
        return 1;
    }

    int d_left = rb_depth(node->left);
    int d_right = rb_depth(node->right);

    if (d_left != d_right) {
        fprintf(stderr, "ERROR: Black height is different: %d - %d\n", d_left, d_right);
        abort();
    }

    return d_left + (node->color == RB_BLACK);
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
    // rb_node * t = rb_get(tree->root, key);

    // if (t == NULL) {
    //     return NULL;
    // }

    // // void * value = t->value;
    // // rb_color color = t->color;

    // if (t->left == NULL) {
    //     // No subtrees, or right subtree only
    //     rb_replace(tree, t, t->right);
    // } else if (t->right == NULL) {
    //     // Left subtree only
    //     rb_replace(tree, t, t->left);
    // } else {
    //     rb_node * m = rb_min(t->right);
    //     rb_move(t, m);
    // }

    // // TODO: balance

    // rb_node * node = rb_get(tree->root, key);

    // if (node == NULL) {
    //     return NULL;
    // }

    // rb_node * t;

    // if (node->left == NULL) {
    //     // No subtrees, or right subtree only
    //     t = node->right;
    //     rb_replace(tree, node, t);
    // } else if (node->right == NULL) {
    //     // Left subtree only
    //     t = node->left;
    //     rb_replace(tree, node, t);
    // } else {
    //     rb_node * m = rb_min(t->right);
    //     rb_move(node, m);
    //     node = m;
    //     t = m->right;
    // }

    // if (node->color == RB_BLACK) {
    //     if (t && t->color == RB_RED) {
    //         t->color = RB_BLACK;
    //     } else {
    //         rb_balance_delete(t);
    //     }
    // }

    // void * value = node->value;

    // free(node->key);
    // free(node);

    // return value;

    fprintf(stderr, "rb_delete(%s)\n", key);

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
        // printf("\n");
    }
}

void rbtree_assert(rb_tree * tree) {

    if (tree->root == NULL) {
        return;
    }

    if (tree->root->color == RB_RED) {
        fprintf(stderr, "ERROR: Root is not black.\n");
        abort();
    }

    int d_left = rb_depth(tree->root->left);
    int d_right = rb_depth(tree->root->right);

    if (d_left != d_right) {
        fprintf(stderr, "ERROR: Black height is different: %d - %d\n", d_left, d_right);
        abort();
    }

    fprintf(stderr, "rbtree_assert(): %d\n", d_left);
}
