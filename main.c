/**
 * @file main.c
 * @author Vikman Fernandez-Castro (victor@wazuh.com)
 * @brief RB tree data structure test
 * @version 0.1
 * @date 2019-08-22
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rbtree.h"

double time_diff(const struct timespec * a, const struct timespec * b) {
    return b->tv_sec - a->tv_sec + (b->tv_nsec - a->tv_nsec) / 1e9;
}

void matrix_free(char ** matrix, int n) {
    for (int i = 0; i < n; i++) {
        free(matrix[i]);
    }

    free(matrix);
}

int main(int argc, char ** argv) {
    // Arguments

    if (argc < 2) {
        fprintf(stderr, "Syntax: %s <N>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize random generator

    char state[256];
    struct random_data data = { 0 };
    initstate_r(time(NULL), state, sizeof(state), &data);

    // Create <N> random keys

    rb_tree * tree = rbtree_init();
    int n = atoi(argv[1]);
    char ** keys = NULL;

    for (int i = 0; i < n; i++) {
        char buffer[64];
        int32_t r;
        random_r(&data, &r);
        snprintf(buffer, sizeof(buffer), "%d", r);

        keys = realloc(keys, sizeof(char *) * (i + 1));
        keys[i] = strdup(buffer);
    }

    // Insert ------------------------------------------------------------------

    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    for (int i = 0; i < n; i++) {
        rbtree_insert(tree, keys[i], keys[i]);
    }

    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    printf("Insert: %.3f ms\n", time_diff(&ts_start, &ts_end) * 1e3);
    // printf("%.3f;", time_diff(&ts_start, &ts_end) * 1e3);

    // Search ------------------------------------------------------------------

    double lapse = 0;

    for (int i = 0; i < n; i++) {
        int32_t r;
        random_r(&data, &r);
        r = r >= 0 ? r % n : -r % n;

        clock_gettime(CLOCK_MONOTONIC, &ts_start);
        rbtree_get(tree, keys[r]);
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        lapse += time_diff(&ts_start, &ts_end);
    }

    printf("Search: %.3f ms\n", lapse * 1e3);
    // printf("%.3f\n", lapse * 1e3);

    // rbtree_print_keys(tree);

    matrix_free(keys, n);
    rbtree_destroy(tree);
    return EXIT_SUCCESS;
}
