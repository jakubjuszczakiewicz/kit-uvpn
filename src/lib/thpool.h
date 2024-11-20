/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __TH_POOL_H__
#define __TH_POOL_H__

#include <stddef.h>

typedef void (*thpool_func)(void *);

struct thpool_t;

struct thpool_t * thpool_create(size_t threads_count, thpool_func func);
void thpool_dispose(struct thpool_t * thpool);

void thpool_push(struct thpool_t * thpool, void * data);

#endif
