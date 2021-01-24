
/*
 * @copyright
 *
 *  Copyright 2017 Neo Natura 
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "share.h"




void shtree_data_set(shtree_t *node, void *data)
{
  node->data = data;
}

void *shtree_data_get(shtree_t *node)
{
  if (!node)
    return (NULL);
  return (node->data);
}

shtree_t *shtree_new(shtree_t *tree, void *data)
{
  shtree_t *node;

  node = (shtree_t *)calloc(1, sizeof(shtree_t));
  if (!node)
    return (NULL);

  if (!tree) {
    /* root node */
    node->root = node;
  } else {
    /* branch or leaf node */
    node->parent = tree;
    node->root = tree->root;
    node->level = tree->level + 1;
    tree->stamp = shtime(); 
  }

  node->data = data;
  node->stamp = shtime();

  return (node);
}

shtree_t *shtree_init(int flags)
{
  shtree_t *root;

  root = shtree_new(NULL, NULL);
  if (!root)
    return (NULL);

  root->flags = flags;

  return (root);
}

void shtree_free_node(shtree_t *node)
{

  /* free leafs first */
  if (node->left)
    shtree_free_node(node->left);
  if (node->right)
    shtree_free_node(node->right);

  if (shtree_root_flags(node) & SHTREE_DEALLOC) {
    if (node->data)
      free(node->data);
  }

  free(node);
}

void shtree_remove_branch(shtree_t *node)
{
  shtree_free_node(node);
}


shtree_t *shtree_left_new(shtree_t *tree, void *data)
{
  shtree_t *node;

  if (tree->left) {
    shtree_remove_branch(tree->left);
    tree->left = NULL;
  }

  node = shtree_new(tree, data);
  if (!node)
    return (NULL);

  node->data = data;
  tree->left = node;

  return (node);
}

shtree_t *shtree_right_new(shtree_t *tree, void *data)
{
  shtree_t *node;

  if (tree->right) {
    shtree_remove_branch(tree->right);
    tree->right = NULL;
  }

  node = shtree_new(tree, data);
  if (!node)
    return (NULL);

  node->data = data;
  tree->right = node;

  return (node);
}

shtree_t *shtree_right(shtree_t *tree)
{
  return (tree->right);
}

shtree_t *shtree_left(shtree_t *tree)
{
  return (tree->left);
}

int shtree_leaf(shtree_t *tree)
{
  return (!tree->left && !tree->right);
}

shtree_t *shtree_root(shtree_t *node)
{
  return (node->root);
}

shtree_t *shtree_parent(shtree_t *node)
{
  return (node->parent);
}

int shtree_flags(shtree_t *node)
{
  return (node->flags);
}

int shtree_root_flags(shtree_t *node)
{

  if (!node || !node->root)
    return (0);

  return (node->root->flags);
}

void shtree_traverse_pre(shtree_t *node, shtree_f proc)
{

  if (!node)
    return;

  (*proc)(node);
  shtree_traverse_pre(node->left, proc);
  shtree_traverse_pre(node->right, proc);

}
void shtree_traverse_in(shtree_t *node, shtree_f proc)
{

  if (!node)
    return;

  shtree_traverse_pre(node->left, proc);
  (*proc)(node);
  shtree_traverse_pre(node->right, proc);

}
void shtree_traverse_post(shtree_t *node, shtree_f proc)
{
  if (!node)
    return;

  shtree_traverse_pre(node->left, proc);
  shtree_traverse_pre(node->right, proc);
  (*proc)(node);
}
void shtree_traverse(shtree_t *node, int order, shtree_f proc)
{

  switch (order) {
    case SHTREE_ORDER_PRE:
      shtree_traverse_pre(node, proc);
      break;
    case SHTREE_ORDER_IN:
      shtree_traverse_in(node, proc);
      break;
    case SHTREE_ORDER_POST:
      shtree_traverse_post(node, proc);
      break;
  }

} 

void shtree_free(shtree_t **tree_p)
{
  shtree_t *tree;

  if (!tree_p)
    return;

  tree = *tree_p;
  *tree_p = NULL;

  if (!tree)
    return;

  shtree_free_node(tree);
//  shtree_traverse(tree, SHTREE_ORDER_POST, shtree_free_node);

}



#define SHTREE_TEST_LIMIT 15
#define LEFT( inx )     (2 * (inx) + 1)
#define RIGHT( inx )    (2 * (inx) + 2)
void TEST_shtree_print(shtree_t *node)
{
//  fprintf(stderr, "DEBUG: SHTREE: \"%s\" (level %d)\n", node->data, node->level);
}
_TEST(shtree)
{
  shtree_t *nodes[32];
  char buf[256];
  int idx;
  
  nodes[0] = shtree_init(SHTREE_DEALLOC);
  for (idx = 0; idx < SHTREE_TEST_LIMIT; idx++) {
    int left = LEFT(idx);
    int right = RIGHT(idx);
    sprintf(buf, "l%d", idx);
    nodes[left] = shtree_left_new(nodes[idx], strdup(buf)); 
    sprintf(buf, "r%d", idx);
    nodes[right] = shtree_right_new(nodes[idx], strdup(buf)); 
  }

  shtree_traverse(nodes[0], SHTREE_ORDER_POST, TEST_shtree_print);

  shtree_free(&nodes[0]);
}

