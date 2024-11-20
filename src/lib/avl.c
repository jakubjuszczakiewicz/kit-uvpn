/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "avl.h"
#include <stdlib.h>
#include <string.h>
#include "allocator.h"
#include "memlog.h"

struct avl_node_t
{
  struct avl_node_t * parent, * left, * right;
  size_t subnodes;
  char data[];
};

struct avl_t
{
  size_t data_size;
  size_t max_elements;
  struct avl_node_t * root;
  allocator_t allocator;
  avl_comparator_t comparator;
};

avl_t avl_create(size_t data_size, size_t max_elements,
    avl_comparator_t comparator)
{
  avl_t avl = int_malloc(sizeof(*avl));

  avl->data_size = data_size;
  avl->max_elements = max_elements;
  avl->root = NULL;
  avl->comparator = comparator;
  avl->allocator = allocator_create(sizeof(struct avl_node_t) + data_size,
      max_elements);

  return avl;
}

void avl_dispose(avl_t avl)
{
  allocator_dispose(avl->allocator);
  int_free(avl);
}

static void rotate_right(avl_t avl, struct avl_node_t * node)
{
  struct avl_node_t * tmp = node->parent;

  if (tmp) {
    if (tmp->left == node)
      tmp->left = node->left;
    else
      tmp->right = node->left;
  } else
    avl->root = node->left;

  node->parent = node->left;
  node->left->parent = tmp;

  tmp = node->left->right;

  node->left->right = node;
  if (tmp)
    tmp->parent = node;
  node->left = tmp;

  size_t left = ((node->left)?(node->left->subnodes + 1):0);
  size_t right = ((node->right)?(node->right->subnodes + 1):0);
  node->subnodes = (left > right)?left:right;

  tmp = node->parent;
  left = ((node->left)?(node->left->subnodes + 1):0);
  right = (node->subnodes + 1);

  tmp->subnodes = (left > right)?left:right;
}

static void rotate_left(avl_t avl, struct avl_node_t * node)
{
  struct avl_node_t * tmp = node->parent;

  if (tmp) {
    if (tmp->left == node)
      tmp->left = node->right;
    else
      tmp->right = node->right;
  } else
    avl->root = node->right;

  node->parent = node->right;
  node->right->parent = tmp;

  tmp = node->right->left;

  node->right->left = node;
  if (tmp)
    tmp->parent = node;
  node->right = tmp;

  size_t left = ((node->left)?(node->left->subnodes + 1):0);
  size_t right = ((node->right)?(node->right->subnodes + 1):0);
  node->subnodes = (left > right)?left:right;

  tmp = node->parent;
  left = (node->subnodes + 1);
  right = ((node->right)?(node->right->subnodes + 1):0);

  tmp->subnodes = (left > right)?left:right;
}

static void avl_rebalance(avl_t avl, struct avl_node_t * node)
{
  while (node != NULL) {
    size_t left = 0, right = 0;
    if (node->left)
      left = 1 + node->left->subnodes;
    if (node->right)
      right = 1 + node->right->subnodes;

    node->subnodes = (left > right)?left:right;

    if (left + 1 < right)
      rotate_left(avl, node);
    else if (right + 1 < left)
      rotate_right(avl, node);

    node = node->parent;
    if (node)
      node = node->parent;
  }
}

int avl_set(avl_t avl, void * data)
{
  struct avl_node_t * root = avl->root, * last = NULL;
  int cmp = 0;

  while (root) {
    cmp = avl->comparator(root->data, data);
    if (cmp == 0) {
      memcpy(root->data, data, avl->data_size);
      return 1;
    }

    last = root;
    if (cmp > 0)
      root = root->left;
    else
      root = root->right;
  }

  if (cmp == 0) {
    avl->root = allocator_new(avl->allocator);
    if (!avl->root)
      return 0;

    avl->root->parent = NULL;
    avl->root->left = NULL;
    avl->root->right = NULL;
    avl->root->subnodes = 0;
    memcpy(avl->root->data, data, avl->data_size);
    return 0;
  }

  root = allocator_new(avl->allocator);
  if (!root)
    return 0;

  if (cmp > 0)
    last->left = root;
  else
    last->right = root;

  root->parent = last;
  root->left = NULL;
  root->right = NULL;
  root->subnodes = 0;
  memcpy(root->data, data, avl->data_size);

  avl_rebalance(avl, root->parent);

  return 1;
}

int avl_get(avl_t avl, void * data)
{
  struct avl_node_t * root = avl->root;

  while (root != NULL) {
    int cmp = avl->comparator(root->data, data);
    if (cmp == 0) {
      memcpy(data, root->data, avl->data_size);
      return 1;
    }

    if (cmp > 0)
      root = root->left;
    else
      root = root->right;
  }

  return 0;
}

static struct avl_node_t * avl_next_node(struct avl_node_t * node)
{
  if (!node)
    return NULL;

  if ((!node->left) && (!node->right)) {
    if (!node->parent)
      return NULL;

    while (node->parent) {
      if (node->parent->left == node)
        return node->parent;
      node = node->parent;
    }

    return NULL;
  }

  if (node->right) {
    node = node->right;
    while (node->left)
      node = node->left;
    return node;
  }

  while (node->parent) {
    if (node->parent->left == node)
      return node->parent;
    node = node->parent;
  }

  return NULL;
}

static struct avl_node_t * avl_first(struct avl_node_t * root)
{
  if (!root)
    return NULL;

  while (root->left)
    root = root->left;

  return root;
}

static struct avl_node_t * avl_delete_node(avl_t avl, struct avl_node_t * node)
{
  if ((!node->left) && (!node->right)) {
    if (!node->parent) {
      allocator_free(avl->allocator, node);
      avl->root = NULL;
      return NULL;
    }

    struct avl_node_t * ret;
    if (node->parent->left == node) {
      node->parent->left = NULL;
      ret = node->parent;
    } else {
      node->parent->right = NULL;
      ret = avl_next_node(node->parent);
    }

    avl_rebalance(avl, node->parent);
    allocator_free(avl->allocator, node);
    return ret;
  }

  if (!node->right) {
    struct avl_node_t * ret;

    if (node->parent) {
      if (node->parent->left == node) {
        node->parent->left = node->left;
        ret = node->parent;
      } else {
        node->parent->right = node->left;
        ret = avl_next_node(node->parent);
      }

      node->left->parent = node->parent;
    } else {
      node->left->parent = NULL;
      avl->root = node->left;
      ret = NULL;
    }

    avl_rebalance(avl, node->parent);
    allocator_free(avl->allocator, node);
    return ret;
  }

  if (!node->left) {
    struct avl_node_t * ret;
    if (node->parent) {
      if (node->parent->left == node) {
        node->parent->left = node->right;
        ret = avl_first(node->right);
      } else {
        node->parent->right = node->right;
        ret = avl_first(node->right);
      }

      node->right->parent = node->parent;
    } else {
      node->right->parent = NULL;
      avl->root = node->right;
      ret = avl->root;
    }

    avl_rebalance(avl, node->parent);
    allocator_free(avl->allocator, node);
    return ret;
  }

  struct avl_node_t * next = node->right;
  while (next->left)
    next = next->left;

  if (next->right) {
    if (next->parent->left == next) {
      next->parent->left = next->right;
    } else {
      next->parent->right = next->right;
    }
    next->right->parent = next->parent;
  } else {
    if (next->parent->left == next) {
      next->parent->left = NULL;
    } else {
      next->parent->right = NULL;
    }
  }

  memcpy(&node->data, &next->data, avl->data_size);

  avl_rebalance(avl, next->parent);
  avl_rebalance(avl, node);

  allocator_free(avl->allocator, next);

  return node;
}


void avl_delete(avl_t avl, void * data)
{
  struct avl_node_t * root = avl->root;
  int cmp = 0;

  while (root != NULL) {
    cmp = avl->comparator(root->data, data);
    if (cmp == 0) {
      avl_delete_node(avl, root);
      return;
    }

    if (cmp > 0)
      root = root->left;
    else
      root = root->right;
  }
}

void avl_delete_if(avl_t avl, avl_comparator_t comparator, void * data)
{
  struct avl_node_t * ret = avl_first(avl->root);

  while (ret) {
    if (comparator(ret->data, data))
      ret = avl_delete_node(avl, ret);
    else
      ret = avl_next_node(ret);
  }
}

static void avl_iterate_node(struct avl_node_t * node,
    void (*callback)(void *, void *), void * callback_data)
{
  if (node->left)
    avl_iterate_node(node->left, callback, callback_data);

  callback(node->data, callback_data);

  if (node->right)
    avl_iterate_node(node->right, callback, callback_data);
}

void avl_iterate_callback(avl_t avl, void (*callback)(void *, void *),
    void * callback_data)
{
  struct avl_node_t * root = avl->root;
  if (root)
    avl_iterate_node(root, callback, callback_data);
}

static size_t avl_size_node(struct avl_node_t * node)
{
  if (!node)
    return 0;
  size_t sum = 1;
  if (node->left)
    sum += avl_size_node(node->left);
  if (node->right)
    sum += avl_size_node(node->right);

  return sum;
}

size_t avl_size(avl_t avl)
{
  return avl_size_node(avl->root);
}
