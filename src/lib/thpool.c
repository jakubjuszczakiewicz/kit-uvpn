/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "thpool.h"
#include <stdlib.h>
#include <stdatomic.h>
#include <semaphore.h>
#include "threads.h"
#include "memlog.h"
#include "rwmutex.h"

#define THPOOL_QUEUE_SIZE 128

struct thpool_t
{
  sem_t wait_sem;

  atomic_uintptr_t ptr[THPOOL_QUEUE_SIZE];
  unsigned int ptr_start;
  atomic_uint ptr_end;
  atomic_uint ptr_fill_1;
  atomic_uint ptr_fill_2;
  
  volatile unsigned int end_now;
  thpool_func func;
  size_t threads_count;
  void * threads[];
};

static void thpool_thread(void * void_data)
{
  struct thpool_t * data = (struct thpool_t *)void_data;

  while (!data->end_now) {
    if (sem_wait_int(&data->wait_sem, &data->end_now))
      break;

    unsigned int fill;
    do {
      fill = atomic_load(&data->ptr_fill_1);
      while ((fill > 0) &&
          (!atomic_compare_exchange_strong(&data->ptr_fill_1, &fill,
          fill - 1)));
      if (fill > 0) {
        unsigned int end = atomic_load(&data->ptr_end);
        void * next_data = (void *)atomic_load(&data->ptr[end]);

        while (!(next_data && atomic_compare_exchange_strong(&data->ptr[end],
            (size_t *)&next_data, 0))) {
          end = atomic_load(&data->ptr_end);
          next_data = (void *)atomic_load(&data->ptr[end]);
        }

        unsigned int new_end, old_end = end;
        do {
          end = old_end;
          new_end = (end + 1) % THPOOL_QUEUE_SIZE;
        } while (!atomic_compare_exchange_strong(&data->ptr_end, &end,
            new_end));

        atomic_fetch_sub(&data->ptr_fill_2, 1);

        data->func(next_data);
      }
    } while (fill > 0);
  }

  sem_post(&data->wait_sem);
}

struct thpool_t * thpool_create(size_t threads_count, thpool_func func)
{
  struct thpool_t * thpool = int_malloc(sizeof(*thpool)
    + threads_count * sizeof(void *));

  sem_init(&thpool->wait_sem, 0, 0);

  for (size_t i = 0; i < THPOOL_QUEUE_SIZE; i++)
    atomic_store(&thpool->ptr[i], 0);

  thpool->ptr_start = 0;
  atomic_store(&thpool->ptr_end, 0);
  atomic_store(&thpool->ptr_fill_1, 0);
  atomic_store(&thpool->ptr_fill_2, 0);

  thpool->end_now = 0;
  thpool->func = func;
  thpool->threads_count = threads_count;
  for (size_t i = 0; i < threads_count; i++)
    thpool->threads[i] = thread_new(thpool_thread, thpool);

  return thpool;
}

void thpool_dispose(struct thpool_t * thpool)
{
  thpool->end_now = 1;
  sem_post(&thpool->wait_sem);

  for (size_t i = 0; i < thpool->threads_count; i++)
    thread_join(thpool->threads[i]);

  sem_destroy(&thpool->wait_sem);

  int_free(thpool);
}

void thpool_push(struct thpool_t * thpool, void * data)
{
  if (!data)
    return;

  while (atomic_load(&thpool->ptr_fill_2) >= THPOOL_QUEUE_SIZE - 1);

  atomic_store(&thpool->ptr[thpool->ptr_start], (size_t)data);
  thpool->ptr_start = (thpool->ptr_start + 1) % THPOOL_QUEUE_SIZE;
  atomic_fetch_add(&thpool->ptr_fill_2, 1);
  atomic_fetch_add(&thpool->ptr_fill_1, 1);

  if (atomic_load(&thpool->ptr_fill_1) <= thpool->threads_count)
    sem_post(&thpool->wait_sem);
}
