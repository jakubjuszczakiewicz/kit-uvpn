/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "workers.h"
#include <thpool.h>
#include <queue.h>
#include <logger.h>
#include <clock.h>
#include "decrypt.h"
#include "checksum.h"
#include "l2_sw.h"
#include "counter.h"
#include "checksum2.h"
#include "encrypt.h"
#include "tcp.h"
#include "tap.h"
#include "connection.h"

extern struct thpool_t * decrypt_thpool;
extern struct thpool_t * encrypt_thpool;
extern struct thpool_t * checksum_thpool;
extern struct thpool_t * checksum2_thpool;

extern struct tap_conn_info tap_conn;

extern rwmutex_t conns_sem;

struct thpool_data
{
  void * data;
  size_t data_size;

  void (*clean_up)(struct queue_desc_t volatile *, unsigned int);
  struct queue_desc_t volatile * cleanup_queue;
  unsigned int cleanup_task_id;

  atomic_int locked;
};

struct thpool_data decrypt_data[MAX_CRYPTO_WORKERS * 4 + 3];
struct thpool_data checksum_data[MAX_CHECKSUM_WORKERS * 4 + 3];
struct thpool_data checksum2_data[MAX_CHECKSUM_WORKERS * 4 + 3];
struct thpool_data encrypt_data[MAX_CRYPTO_WORKERS * 4 + 3];

void decrypt_init(void)
{
  for (size_t i = 0; i < sizeof(decrypt_data) / sizeof(decrypt_data[0]); i++) {
    atomic_store(&decrypt_data[i].locked, 0);
  }
}

void decrypt_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  decrypt_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void decrypt_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&decrypt_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(decrypt_data) / sizeof(decrypt_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &decrypt_data[idx];
  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(decrypt_thpool, th_data);
}

void checksum_init(void)
{
  for (size_t i = 0; i < sizeof(checksum_data) / sizeof(checksum_data[0]);
      i++) {
    atomic_store(&checksum_data[i].locked, 0);
  }
}

void checksum_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  checksum_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void checksum_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&checksum_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(checksum_data) / sizeof(checksum_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &checksum_data[idx];

  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(checksum_thpool, th_data);
}

void crypto_in_init(void)
{
  for (size_t i = 0; i < sizeof(decrypt_data) / sizeof(decrypt_data[0]);
      i++) {
    atomic_store(&decrypt_data[i].locked, 0);
  }
}

void crypto_in_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  decrypt_worker(data->data, data->data_size);
  checksum_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void crypto_in_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&decrypt_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(decrypt_data) / sizeof(decrypt_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &decrypt_data[idx];

  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(decrypt_thpool, th_data);
}

void l2_sw_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  l2_sw_worker(data, data_size);
  clean_up(cleanup_queue, cleanup_task_id);
}

void counter_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  counter_worker(data, data_size);
  clean_up(cleanup_queue, cleanup_task_id);
}

void checksum2_init(void)
{
  for (size_t i = 0; i < sizeof(checksum2_data) / sizeof(checksum2_data[0]);
      i++) {
    atomic_store(&checksum2_data[i].locked, 0);
  }
}

void checksum2_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  checksum2_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void checksum2_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&checksum2_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(checksum2_data) / sizeof(checksum2_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &checksum2_data[idx];

  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(checksum2_thpool, th_data);
}

void encrypt_init(void)
{
  for (size_t i = 0; i < sizeof(encrypt_data) / sizeof(encrypt_data[0]); i++) {
    atomic_store(&encrypt_data[i].locked, 0);
  }
}

void encrypt_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  encrypt_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void encrypt_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&encrypt_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(encrypt_data) / sizeof(encrypt_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &encrypt_data[idx];
  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(encrypt_thpool, th_data);
}

void crypto_out_init(void)
{
  for (size_t i = 0; i < sizeof(encrypt_data) / sizeof(encrypt_data[0]);
      i++) {
    atomic_store(&encrypt_data[i].locked, 0);
  }
}

void crypto_out_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  checksum2_worker(data->data, data->data_size);
  encrypt_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

void crypto_out_consumer(void * data, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;
  int expected = 0;

  while ((!end_now) &&
      (!atomic_compare_exchange_strong(&encrypt_data[idx].locked, &expected,
      1))) {
    idx = (idx + 1) % (sizeof(encrypt_data) / sizeof(encrypt_data[0]));
    expected = 0;
  }

  struct thpool_data * th_data = &encrypt_data[idx];

  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(encrypt_thpool, th_data);
}

void conn_consumer(void * data_void, size_t data_size,
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int),
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  struct packet_record * data = (struct packet_record *)data_void;

  if ((data->msg_type == MSG_TYPE_RAW_NET) &&
      (data->destination == TAP_CONN_ID) &&
      (tap_conn.dev_sock[0] > 0)) {
    tap_worker(&tap_conn, data, data_size);
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  if (data->destination == TAP_CONN_ID) {
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  if ((data->destination < 1) || (data->destination & 0xFFFF) < 1) {
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  if (data->msg_type == MSG_TYPE_INVALID) {
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  int dest = CONN_ID_NUM(data->destination);

  i_rwlock_rdlock(&conns_sem);
  if (tcp_conn[dest].conn_id == data->destination)
    tcp_worker(&tcp_conn[dest], data, data_size);
  i_rwlock_rdunlock(&conns_sem);

  clean_up(cleanup_queue, cleanup_task_id);
}
