/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "queue.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <semaphore.h>
#include "utils.h"
#include "threads.h"
#include "clock.h"
#include "memlog.h"

#define QUEUE_POINTER_BITS 16

#define QUEUE_MAX_SERVICES_CONSUMER_TYPES 16
#define QUEUE_LOCK_VISITED_BITS ((1U << QUEUE_MAX_SERVICES_CONSUMER_TYPES) - 1)

struct queue_entry_t
{
  atomic_uint consumer; // fix in init
  unsigned int data_size;
  char data[QUEUE_DATA_SIZE];
};

struct queue_consumers_info_t
{
  queue_worker_t worker;
  void * thread;
  unsigned int queue_end;
  sem_t queue_sem;
};

struct queue_desc_t
{
  struct queue_entry_t * queue_data;

  unsigned int end_now;
  atomic_ulong fill;
  atomic_ulong start;
  unsigned int size;
  unsigned int consumers_count;

  struct queue_consumers_info_t consumers_info[];
};

struct queue_info_t
{
  struct queue_desc_t * queue;
  unsigned int consumer_id;
};

struct queue_task_info
{
  struct queue_desc_t volatile * queue;
  unsigned int taks_id;
};

void queue_consumer_thread_clean_up(struct queue_desc_t volatile * queue,
    unsigned int taks_id)
{
  unsigned int consumer_id =
      atomic_load(&queue->queue_data[taks_id].consumer);
  atomic_fetch_add(&queue->queue_data[taks_id].consumer, 1);

  sem_post((sem_t *)&queue->consumers_info[consumer_id].queue_sem);
}

void queue_consumer_thread(void * queue_info_void)
{
  struct queue_info_t * queue_info = (struct queue_info_t *)queue_info_void;
  struct queue_desc_t volatile * queue =
    (struct queue_desc_t volatile *)queue_info->queue;
  struct queue_consumers_info_t * consumer_info =
    (struct queue_consumers_info_t *)
    &queue_info->queue->consumers_info[queue_info->consumer_id];

  while (!queue->end_now) {
    sem_wait(&consumer_info->queue_sem);

    while (!queue->end_now) {
      unsigned int idx = consumer_info->queue_end;

      if (atomic_load(&queue->queue_data[idx].consumer) <
          queue_info->consumer_id + 1)
        break;
      if (atomic_load(&queue->queue_data[idx].consumer) >
          queue_info->consumer_id + 1) {
        consumer_info->queue_end = (idx + 1) % queue->size;
        continue;
      }

      consumer_info->worker(&queue->queue_data[idx].data,
          queue->queue_data[idx].data_size, queue_consumer_thread_clean_up,
          queue, idx);
      consumer_info->queue_end = (idx + 1) % queue->size;
    }
  }

  int_free(queue_info_void);
}

void queue_cleanup_thread(void * queue_info_void)
{
  struct queue_info_t * queue_info = (struct queue_info_t *)queue_info_void;
  struct queue_desc_t volatile * queue =
    (struct queue_desc_t volatile *)queue_info->queue;
  struct queue_consumers_info_t * consumer_info =
    (struct queue_consumers_info_t *)
    &queue_info->queue->consumers_info[queue_info->consumer_id];

  while (!queue->end_now) {
    sem_wait(&consumer_info->queue_sem);

    while (!queue->end_now) {
      unsigned int idx = consumer_info->queue_end;

      if (atomic_load(&queue->queue_data[idx].consumer) <
          queue_info->consumer_id + 1)
        break;
      if (atomic_load(&queue->queue_data[idx].consumer) >
          queue_info->consumer_id + 1) {
        consumer_info->queue_end = (consumer_info->queue_end + 1) % queue->size;
        continue;
      }

      // memset(&queue->queue_data[idx].data, 0, queue->queue_data[idx].data_size);
      queue->queue_data[idx].data_size = 0;
      atomic_store(&queue->queue_data[idx].consumer, 0);
      atomic_fetch_sub(&queue->fill, 1);

      consumer_info->queue_end = (consumer_info->queue_end + 1) % queue->size;
    }
  }

  int_free(queue_info_void);
}

queue_stat_t queue_init(queue_t * queue, unsigned int p2size,
    unsigned int consumers_count, queue_worker_t consumers[])
{
  if (p2size > QUEUE_POINTER_BITS)
    return QUEUE_STAT_INVALID_ARGUMENT_ERROR;

  struct queue_desc_t * queue_desc = int_malloc(sizeof(* queue_desc) +
      sizeof(queue_desc->consumers_info[0]) * (consumers_count + 1));
  
  unsigned int size = 1 << p2size;

  queue_desc->queue_data = int_malloc(sizeof(struct queue_entry_t) * size);
  memset(queue_desc->queue_data, 0, sizeof(struct queue_entry_t) * size);

  queue_desc->end_now = 0;
  atomic_store(&queue_desc->start, 0);
  atomic_store(&queue_desc->fill, 0);
  queue_desc->size = size;
  queue_desc->consumers_count = consumers_count + 1;

  for (unsigned int i = 0; i < consumers_count; i++) {
    queue_desc->consumers_info[i].worker = consumers[i];
    queue_desc->consumers_info[i].queue_end = 0;
    sem_init(&queue_desc->consumers_info[i].queue_sem, 0, 1);
    struct queue_info_t * info = int_malloc(sizeof(*info));
    info->queue = queue_desc;
    info->consumer_id = i;

    queue_desc->consumers_info[i].thread =
        thread_new(queue_consumer_thread, info);
  }

  queue_desc->consumers_info[consumers_count].worker = NULL;
  queue_desc->consumers_info[consumers_count].queue_end = 0;
  sem_init(&queue_desc->consumers_info[consumers_count].queue_sem, 0, 1);
  struct queue_info_t * info = int_malloc(sizeof(*info));
  info->queue = queue_desc;
  info->consumer_id = consumers_count;

  queue_desc->consumers_info[consumers_count].thread =
      thread_new(queue_cleanup_thread, info);

  *queue = queue_desc;

  return QUEUE_STAT_OK;
}

queue_stat_t queue_close(queue_t queue)
{
  queue->end_now = 1;

  for (unsigned int i = 0; i < queue->consumers_count; i++)
    sem_post(&queue->consumers_info[i].queue_sem);

  for (unsigned int i = 0; i < queue->consumers_count; i++)
    thread_join(queue->consumers_info[i].thread);

  for (unsigned int i = 0; i < queue->consumers_count; i++)
    sem_destroy(&queue->consumers_info[i].queue_sem);

  int_free(queue->queue_data);

  memset(queue, 0, sizeof(*queue));
  int_free(queue);

  return QUEUE_STAT_OK;
}

double queue_fill_ratio(queue_t queue)
{
  return (double)atomic_load(&queue->fill) / queue->size;
}

queue_stat_t queue_enqueue(queue_t queue, const void * data, size_t data_size,
    unsigned int needs_int_free, uint64_t timeout_ns)
{
  if (data_size > QUEUE_DATA_SIZE)
      return QUEUE_STAT_INVALID_ARGUMENT_ERROR;

  uint64_t now = getnow_monotonic();
  uint64_t deadline = now + timeout_ns;

  unsigned long fill, start = 0;
  while ((now = getnow_monotonic()) < deadline) {
    fill = atomic_load(&queue->fill);
    if (fill + needs_int_free < queue->size) {
      start = atomic_load(&queue->start);
      unsigned long new_start = (start + 1) % queue->size;
      if (atomic_compare_exchange_strong(&queue->start, &start, new_start))
        break;
    }
  }

  if (now >= deadline)
    return QUEUE_STAT_TIMEOUT_WARNING;

  if (queue->end_now)
    return QUEUE_STAT_INTERNAL_ERROR;

  atomic_fetch_add(&queue->fill, 1);

  memcpy(&queue->queue_data[start].data, data, data_size);
  queue->queue_data[start].data_size = data_size;
  atomic_store(&queue->queue_data[start].consumer, 1);

  sem_post((sem_t *)&queue->consumers_info[0].queue_sem);

  return QUEUE_STAT_OK;
}
