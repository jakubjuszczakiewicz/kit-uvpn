/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>

typedef void (*thpool_func)(void *);

struct thpool_t;

struct thpool_t * thpool_create(size_t threads_count, thpool_func func);
void thpool_dispose(struct thpool_t * thpool);

void thpool_push(struct thpool_t * thpool, void * data);
