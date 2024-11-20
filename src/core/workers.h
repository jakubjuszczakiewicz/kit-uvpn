/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __WORKERS_H__
#define __WORKERS_H__

#include <stddef.h>
#include <queue.h>
#include "global.h"

void decrypt_init(void);

void decrypt_thread_executor(void * data_void);

void decrypt_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void checksum_init(void);

void checksum_thread_executor(void * data_void);

void checksum_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void crypto_in_init(void);

void crypto_in_thread_executor(void *data_void);

void crypto_in_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void l2_sw_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void counter_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void checksum2_init(void);

void checksum2_thread_executor(void * data_void);

void checksum2_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void encrypt_init(void);

void encrypt_thread_executor(void * data_void);

void encrypt_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void crypto_out_init(void);

void crypto_out_thread_executor(void *data_void);

void crypto_out_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

void conn_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

#endif
