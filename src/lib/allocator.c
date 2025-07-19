/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "allocator.h"

#include <stdlib.h>
#include <string.h>
#include "memlog.h"

struct allocator_t
{
  size_t block_size;
  size_t block_count;
  size_t data_offset;
  size_t first_int_free_idx;
  char data[];
};

allocator_t allocator_create(size_t block_size, size_t block_count)
{
  block_size = (block_size + sizeof(size_t) - 1) / sizeof(size_t);
  block_size *= sizeof(size_t);

  block_count = (block_count + 7) / 8;
  block_count *= 8;

  size_t size = sizeof(struct allocator_t) + block_size * block_count +
      (block_count / 8);

  allocator_t allocator = int_malloc(size);
  memset(allocator, 0, size);

  allocator->block_size = block_size;
  allocator->block_count = block_count;
  allocator->data_offset = block_count / 8;
  allocator->first_int_free_idx = 0;

  return allocator;
}

void allocator_dispose(allocator_t allocator)
{
  int_free(allocator);
}

void * allocator_new(allocator_t allocator)
{
  if (allocator->first_int_free_idx == -1)
    return NULL;

  size_t idx = allocator->first_int_free_idx;

  if (allocator->data[idx >> 3] & (1U << (idx & 0x7))) {
    for(idx = 0; idx < allocator->block_count; idx++)
      if ((allocator->data[idx >> 3] & (1U << (idx & 0x7))) == 0)
        break;
    if (idx == allocator->block_count)
      return NULL;
  }

  allocator->data[idx >> 3] |= (1U << (idx & 0x7));

  char * data = &allocator->data[allocator->data_offset];

  size_t new_idx = idx;
  for(new_idx = idx + 1; new_idx < allocator->block_count; new_idx++)
    if ((allocator->data[new_idx >> 3] & (1U << (new_idx & 0x7))) == 0)
      break;

  if (new_idx == allocator->block_count)
    new_idx = -1;

  allocator->first_int_free_idx = new_idx;

  return &data[allocator->block_size * idx];
}

void allocator_free(allocator_t allocator, void * block_void)
{
  char * block = (char *)block_void;
  char * data = &allocator->data[allocator->data_offset];

  size_t offs = block - data;
  if (offs % allocator->block_size != 0)
    return;

  size_t idx = offs / allocator->block_size;

  if ((allocator->data[idx >> 3] & (1U << (idx & 0x7))) == 0)
    return;

  allocator->data[idx >> 3] ^= (1U << (idx & 0x7));

  if (idx < allocator->first_int_free_idx)
    allocator->first_int_free_idx = idx;
}
