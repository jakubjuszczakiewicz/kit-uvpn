/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __PERF_H__
#define __PERF_H__

#ifdef PERF_COUNTERS

#include <stdatomic.h>
#include <stdint.h>
#include "global.h"

struct perf_counters
{
  int interval;
  uint64_t last_dump;

  atomic_ullong enqueue;
  atomic_ullong enqueue_ctr;
  atomic_ullong decrypt;
  atomic_ullong decrypt_ctr;
  atomic_ullong checksum;
  atomic_ullong checksum_ctr;
  atomic_ullong l2_sw;
  atomic_ullong l2_sw_ctr;
  atomic_ullong counter;
  atomic_ullong counter_ctr;
  atomic_ullong checksum2;
  atomic_ullong checksum2_ctr;
  atomic_ullong encrypt;
  atomic_ullong encrypt_ctr;
  atomic_ullong tcp_dequeue;
  atomic_ullong tcp_dequeue_ctr;
  atomic_ullong tcp_send;
  atomic_ullong tcp_send_ctr;
  atomic_ullong pkg_process;
  atomic_ullong pkg_process_ctr;
  atomic_ullong pkg_process_to_decrypt;
  atomic_ullong pkg_process_to_decrypt_ctr;
  atomic_ullong pkg_process_to_checksum;
  atomic_ullong pkg_process_to_checksum_ctr;
  atomic_ullong pkg_process_to_l2_sw;
  atomic_ullong pkg_process_to_l2_sw_ctr;
  atomic_ullong pkg_process_to_counter;
  atomic_ullong pkg_process_to_counter_ctr;
  atomic_ullong pkg_process_to_checksum2;
  atomic_ullong pkg_process_to_checksum2_ctr;
  atomic_ullong pkg_process_to_encrypt;
  atomic_ullong pkg_process_to_encrypt_ctr;
  atomic_ullong conf_sem_wait;
  atomic_ullong conf_sem_wait_ctr;
  atomic_ullong tap_write;
  atomic_ullong tap_write_ctr;
  atomic_ullong tap_read;
  atomic_ullong tap_read_ctr;
  atomic_ullong tcp_write;
  atomic_ullong tcp_write_ctr;
  atomic_ullong tcp_read;
  atomic_ullong tcp_read_ctr;
};


void perf_init(struct perf_counters * perf_counters);
void dump_perf_counters(const char * path,
    const struct perf_counters * perf_counters, double queue_fill);

#endif
#endif
