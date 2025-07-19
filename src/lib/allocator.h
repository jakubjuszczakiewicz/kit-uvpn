/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>


typedef struct allocator_t * allocator_t;

allocator_t allocator_create(size_t block_size, size_t block_count);
void allocator_dispose(allocator_t allocator);
void * allocator_new(allocator_t allocator);
void allocator_free(allocator_t allocator, void * block);
