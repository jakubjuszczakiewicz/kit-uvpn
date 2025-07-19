/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <sys/types.h>
#include <stdint.h>

#define QUEUE_STAT_OK 0
#define QUEUE_STAT_SYSTEM_ERROR 1
#define QUEUE_STAT_INTERNAL_ERROR 2
#define QUEUE_STAT_OUT_OF_MEMORY_ERROR 3
#define QUEUE_STAT_INVALID_ARGUMENT_ERROR 4
#define QUEUE_STAT_DEQUEUE_WITH_NON_CONSUMER_ERROR 5
#define QUEUE_STAT_FULL_QUEUE_WARNING 6
#define QUEUE_STAT_EMPTY_QUEUE_WARNING 7
#define QUEUE_STAT_TIMEOUT_WARNING 8

#ifndef QUEUE_DATA_SIZE
#define QUEUE_DATA_SIZE 2048
#endif

#define MAX_SERVICE_NAME_LEN 64

#define QUEUE_WORKER_STAT_FALSE 0
#define QUEUE_WORKER_STAT_TRUE  1

typedef int queue_stat_t;
typedef int queue_test_stat_t;

typedef struct queue_desc_t * queue_t;

typedef void (*queue_worker_t)(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile *, unsigned int);

/* init and close aren't thread safe */
queue_stat_t queue_init(queue_t * queue, unsigned int p2size,
    unsigned int consumers_count, queue_worker_t consumers[]);
queue_stat_t queue_close(queue_t queue);

queue_stat_t queue_enqueue(queue_t queue, const void * data, size_t data_size,
    unsigned int needs_free, uint64_t timeout_ns);
double queue_fill_ratio(queue_t queue);
