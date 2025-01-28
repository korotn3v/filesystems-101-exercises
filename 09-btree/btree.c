#include <solution.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct Node {
    int leaf, min_degree, curr_values_cnt;
    int *values;
    struct Node **links;
};

struct btree {
    int min_degree;
    struct Node *root;
};

struct Node *init_node(int leaf, unsigned int L) {
    struct Node *top = (struct Node *) calloc(1, sizeof(struct Node));
    top->leaf = leaf;
    top->min_degree = L;
    top->curr_values_cnt = 0;
    top->values = (int *) calloc((2 * L), sizeof(int));
    top->links = (struct Node **) calloc((2 * L + 1), sizeof(struct Node *));
    return top;
}

struct btree *btree_alloc(unsigned int L) {
    struct btree *b_tree = (struct btree *) calloc(1, sizeof(struct btree));
    b_tree->root = NULL;
    b_tree->min_degree = L;
    return b_tree;
}

void free_node(struct Node *top) {
    if (!top) {
        return;
    }
    if (!top->leaf) {
        for (int i = 0; i < top->curr_values_cnt + 1; ++i) {
            free_node(top->links[i]);
        }
    }
    free(top->links);
    free(top->values);
    free(top);
}

static void delete_node(struct Node *top) {
    free(top->links);
    free(top->values);
    free(top);
}

void btree_free(struct btree *min_degree) {
    free_node(min_degree->root);
    free(min_degree);
}

static void link_decompose(struct Node *node, int k) {
    int min_degree = node->min_degree;
    struct Node *node1 = node->links[k];
    struct Node *node2 = init_node(node1->leaf, min_degree);
    node2->curr_values_cnt = min_degree - 1;
    int i;
    for (i = 0; i < min_degree - 1; ++i) {
        node2->values[i] = node1->values[i + min_degree];
    }
    if (node1->leaf == 0) {
        for (i = 0; i < min_degree; ++i) {
            node2->links[i] = node1->links[i + min_degree];
        }
    }
    node1->curr_values_cnt = min_degree - 1;
    for (int i = node->curr_values_cnt; i >= k + 1; --i) {
        node->links[i + 1] = node->links[i];
    }
    node->links[k + 1] = node2;
    for (int i = node->curr_values_cnt - 1; i >= k; --i) {
        node->values[i + 1] = node->values[i];
    }
    node->values[k] = node1->values[min_degree - 1];
    node->curr_values_cnt += 1;
}

static void insert_incomplete(struct Node *node, int k) {
    int i = node->curr_values_cnt - 1;
    if (node->leaf != 1) {
        while (i >= 0 && node->values[i] > k) {
            --i;
        }
        if (node->links[i + 1]->curr_values_cnt == 2 * node->min_degree - 1) {
            link_decompose(node, i + 1);
            if (k > node->values[i + 1]) {
                ++i;
            }
        }
        insert_incomplete(node->links[i + 1], k);

    } else {
        while (i >= 0 && node->values[i] > k) {
            node->values[i + 1] = node->values[i];
            --i;
        }
        node->values[i + 1] = k;
        node->curr_values_cnt += 1;
    }
}

void btree_insert(struct btree *t, int x) {
    if (btree_contains(t, x)) return;
    if (!t->root) {
        t->root = init_node(true, t->min_degree);
        t->root->values[0] = x;
        t->root->curr_values_cnt = 1;
        return;
    }
    int min_degree = t->min_degree;
    struct Node *top = t->root;
    if (top->curr_values_cnt == 2 * min_degree - 1) {
        struct Node *node = init_node(0, min_degree);
        node->links[0] = top;
        link_decompose(node, 0);
        int i = 0;
        if (node->values[0] < x) {
            ++i;
        }
        insert_incomplete(node->links[i], x);
        t->root = node;
    } else {
        insert_incomplete(top, x);
    }
}

static void merge_values(struct Node *node, int k) {
    if (!node) {
        return;
    }
    struct Node *left = node->links[k];
    struct Node *right = node->links[k + 1];

    left->values[node->min_degree - 1] = node->values[k];
    for (int i = 0; i < right->min_degree - 1; ++i) {
        left->values[i + node->min_degree] = right->values[i];
    }
    if (!left->leaf) {
        for (int i = 0; i < right->min_degree; ++i) {
            left->links[i + node->min_degree] = right->links[i];
        }
    }
    left->curr_values_cnt = 2 * left->min_degree - 1;
    for (int j = k; j < node->curr_values_cnt - 1; ++j) {
        node->values[j] = node->values[j + 1];
    }
    for (int j = k + 1; j < node->curr_values_cnt; ++j) {
        node->links[j] = node->links[j + 1];
    }
    --node->curr_values_cnt;
    delete_node(right);
}

static void value_del(struct Node *node, int x) {
    if (!node) {
        return;
    }
    int k = 0;
    while (k < node->curr_values_cnt && x > node->values[k]) {
        ++k;
    }
    if (k < node->curr_values_cnt && x == node->values[k]) {
        if (node->leaf) {
            for (long int i = k; i < node->curr_values_cnt - 1; ++i) {
                node->values[i] = node->values[i + 1];
            }
            --(node->curr_values_cnt);
            return;
        }
        if (node->links[k]->curr_values_cnt >= node->min_degree) {
            struct Node *cur = node->links[k];
            while (!cur->leaf) {
                cur = cur->links[cur->curr_values_cnt];
            }
            int value = cur->values[cur->curr_values_cnt - 1];
            node->values[k] = value;
            value_del(node->links[k], value);
        } else if (node->links[k + 1]->curr_values_cnt >= node->min_degree) {
            struct Node *cur = node->links[k + 1];
            while (!cur->leaf) {
                cur = cur->links[0];
            }
            int value = cur->values[0];
            node->values[k] = value;
            value_del(node->links[k + 1], value);
        } else {
            merge_values(node, k);
            value_del(node->links[k], x);
        }
    } else {
        if (node->leaf) {
            return;
        }
        if (node->links[k]->curr_values_cnt == node->min_degree - 1) {
            if ((k > 0 && node->links[k - 1]->curr_values_cnt >= node->min_degree) ||
                (k < node->curr_values_cnt && node->links[k + 1]->curr_values_cnt >= node->min_degree)) {
                if (k > 0 && node->links[k - 1]->curr_values_cnt >= node->min_degree) {
                    struct Node *left = node->links[k];
                    struct Node *right = node->links[k - 1];
                    for (int i = left->curr_values_cnt - 1; i >= 0; --i) {
                        left->values[i + 1] = left->values[i];
                    }
                    if (!left->leaf) {
                        for (int i = left->curr_values_cnt; i >= 0; --i) {
                            left->links[i + 1] = left->links[i];
                        }
                    }
                    ++left->curr_values_cnt;
                    left->values[0] = node->values[k - 1];
                    if (!left->leaf) {
                        left->links[0] = right->links[right->curr_values_cnt];
                    }
                    node->values[k - 1] = right->values[right->curr_values_cnt - 1];
                    --right->curr_values_cnt;
                } else {
                    struct Node *left = node->links[k];
                    struct Node *right = node->links[k + 1];
                    left->values[left->curr_values_cnt] = node->values[k];
                    ++left->curr_values_cnt;
                    if (!left->leaf) {
                        left->links[left->curr_values_cnt] = right->links[0];
                    }
                    node->values[k] = right->values[0];
                    for (long int i = 0; i < right->curr_values_cnt - 1; ++i) {
                        right->values[i] = right->values[i + 1];
                    }
                    if (!right->leaf) {
                        for (long int i = 0; i < right->curr_values_cnt + 1; ++i) {
                            right->links[i] = right->links[i + 1];
                        }
                    }
                    --node->links[k + 1]->curr_values_cnt;
                }
            } else {
                if (k > 0) {
                    merge_values(node, k - 1);
                    --k;
                } else {
                    merge_values(node, k);
                }
            }
        }
        value_del(node->links[k], x);
        if (node->curr_values_cnt == 0) {
            node = node->links[k];
        }
    }
}

void btree_delete(struct btree *t, int x) {
    if (!btree_contains(t, x)) {
        return;
    }
    if (!t->root) {
        return;
    }
    value_del(t->root, x);
    if (t->root->curr_values_cnt == 0) {
        struct Node *root = t->root;
        if (t->root->leaf) {
            t->root = NULL;
        } else {
            t->root = t->root->links[0];
        }
        delete_node(root);
    }
}

bool node_contains(struct Node *node, int x) {
    if (!node) {
        return false;
    }
    int i = 0;
    while (i < node->curr_values_cnt && x > node->values[i]) {
        ++i;
    }
    if (i < node->curr_values_cnt && node->values[i] == x) {
        return true;
    }
    if (node->leaf) {
        return false;
    }
    return node_contains(node->links[i], x);
}

bool btree_contains(struct btree *t, int x) {
    return node_contains(t->root, x);
}

struct btree_iter;

int count_value(struct Node *top) {
    if (!top) {
        return 0;
    }
    int cnt = top->curr_values_cnt;
    if (top->leaf) {
    } else {
        for (int i = 0; i <= top->curr_values_cnt; ++i) {
            cnt += count_value(top->links[i]);
        }
    }
    return cnt;
}

static void btree_traverse(struct Node *node, int *iter, int *k) {
    if (!node) {
        return;
    }
    for (int i = 0; i < node->curr_values_cnt; ++i) {
        if (!node->leaf) {
            btree_traverse(node->links[i], iter, k);
        }
        iter[*k] = node->values[i];
        ++(*k);
    }
    if (!node->leaf) {
        btree_traverse(node->links[node->curr_values_cnt], iter, k);
    }
}

struct btree_iter {
    int *value_pointers;
    int counter;
    int j;
};

struct btree_iter *btree_iter_start(struct btree *t) {
    struct btree_iter *iter = (struct btree_iter *) calloc(1, sizeof(struct btree_iter));
    int counter = count_value(t->root);
    iter->counter = counter;
    iter->value_pointers = calloc(counter, sizeof(int));
    int k = 0;
    btree_traverse(t->root, iter->value_pointers, &k);
    return iter;
}

void btree_iter_end(struct btree_iter *i) {
    free(i->value_pointers);
    free(i);
}

bool btree_iter_next(struct btree_iter *i, int *x) {
    if (i->j == i->counter) {
        return false;
    }
    *x = i->value_pointers[i->j];
    ++i->j;
    return true;
}