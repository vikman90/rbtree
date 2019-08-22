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

typedef enum rb_color { RB_RED, RB_BLACK } rb_color;

typedef struct rb_node {
    char * key;
    void * value;
    rb_color color;
    struct rb_node * parent;
    struct rb_node * left;
    struct rb_node * right;
} rb_node;

typedef struct rb_tree {
    rb_node * root;
} rb_tree;

rb_tree * rbtree_init();
void rbtree_destroy(rb_tree * tree);
int rbtree_insert(rb_tree * tree, const char * key, void * value);
void * rbtree_get(rb_tree * tree, const char * key);
void * rbtree_delete(rb_tree * tree, const char * key);
void * rbtree_minimum(rb_tree * tree);
void * rbtree_maximum(rb_tree * tree);
void rbtree_print_keys(rb_tree * tree);

#endif
