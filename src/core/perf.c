/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "perf.h"
#include <stdio.h>

#ifdef PERF_COUNTERS

#define STRTIME_SIZE 32

void perf_init(struct perf_counters * perf_counters)
{
  atomic_store(&perf_counters->enqueue, 0);
  atomic_store(&perf_counters->enqueue_ctr, 0);
  atomic_store(&perf_counters->decrypt, 0);
  atomic_store(&perf_counters->decrypt_ctr, 0);
  atomic_store(&perf_counters->checksum, 0);
  atomic_store(&perf_counters->checksum_ctr, 0);
  atomic_store(&perf_counters->l2_sw, 0);
  atomic_store(&perf_counters->l2_sw_ctr, 0);
  atomic_store(&perf_counters->counter, 0);
  atomic_store(&perf_counters->counter_ctr, 0);
  atomic_store(&perf_counters->checksum2, 0);
  atomic_store(&perf_counters->checksum2_ctr, 0);
  atomic_store(&perf_counters->encrypt, 0);
  atomic_store(&perf_counters->encrypt_ctr, 0);
  atomic_store(&perf_counters->tcp_dequeue, 0);
  atomic_store(&perf_counters->tcp_dequeue_ctr, 0);
  atomic_store(&perf_counters->tcp_send, 0);
  atomic_store(&perf_counters->tcp_send_ctr, 0);
  atomic_store(&perf_counters->pkg_process, 0);
  atomic_store(&perf_counters->pkg_process_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_decrypt, 0);
  atomic_store(&perf_counters->pkg_process_to_decrypt_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_checksum, 0);
  atomic_store(&perf_counters->pkg_process_to_checksum_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_l2_sw, 0);
  atomic_store(&perf_counters->pkg_process_to_l2_sw_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_counter, 0);
  atomic_store(&perf_counters->pkg_process_to_counter_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_checksum2, 0);
  atomic_store(&perf_counters->pkg_process_to_checksum2_ctr, 0);
  atomic_store(&perf_counters->pkg_process_to_encrypt, 0);
  atomic_store(&perf_counters->pkg_process_to_encrypt_ctr, 0);
  atomic_store(&perf_counters->conf_sem_wait, 0);
  atomic_store(&perf_counters->conf_sem_wait_ctr, 0);
  atomic_store(&perf_counters->tap_write, 0);
  atomic_store(&perf_counters->tap_write_ctr, 0);
  atomic_store(&perf_counters->tap_read, 0);
  atomic_store(&perf_counters->tap_read_ctr, 0);
  atomic_store(&perf_counters->tcp_write, 0);
  atomic_store(&perf_counters->tcp_write_ctr, 0);
  atomic_store(&perf_counters->tcp_read, 0);
  atomic_store(&perf_counters->tcp_read_ctr, 0);
}

void dump_perf_counters(const char * path,
    const struct perf_counters * perf_counters, double queue_fill)
{
  FILE * f = fopen(path, "w");
  if (!f)
    return;

  unsigned long long enqueue = atomic_load(&perf_counters->enqueue);
  unsigned long long enqueue_ctr = atomic_load(&perf_counters->enqueue_ctr);
  unsigned long long decrypt = atomic_load(&perf_counters->decrypt);
  unsigned long long decrypt_ctr = atomic_load(&perf_counters->decrypt_ctr);
  unsigned long long checksum = atomic_load(&perf_counters->checksum);
  unsigned long long checksum_ctr = atomic_load(&perf_counters->checksum_ctr);
  unsigned long long l2_sw = atomic_load(&perf_counters->l2_sw);
  unsigned long long l2_sw_ctr = atomic_load(&perf_counters->l2_sw_ctr);
  unsigned long long counter = atomic_load(&perf_counters->counter);
  unsigned long long counter_ctr = atomic_load(&perf_counters->counter_ctr);
  unsigned long long checksum2 = atomic_load(&perf_counters->checksum2);
  unsigned long long checksum2_ctr = atomic_load(&perf_counters->checksum2_ctr);
  unsigned long long encrypt = atomic_load(&perf_counters->encrypt);
  unsigned long long encrypt_ctr = atomic_load(&perf_counters->encrypt_ctr);
  unsigned long long tcp_dequeue = atomic_load(&perf_counters->tcp_dequeue);
  unsigned long long tcp_dequeue_ctr =
      atomic_load(&perf_counters->tcp_dequeue_ctr);
  unsigned long long tcp_send = atomic_load(&perf_counters->tcp_send);
  unsigned long long tcp_send_ctr = atomic_load(&perf_counters->tcp_send_ctr);
  unsigned long long pkg_process = atomic_load(&perf_counters->pkg_process);
  unsigned long long pkg_process_ctr =
      atomic_load(&perf_counters->pkg_process_ctr);
  unsigned long long pkg_process_to_decrypt =
      atomic_load(&perf_counters->pkg_process_to_decrypt);
  unsigned long long pkg_process_to_decrypt_ctr =
      atomic_load(&perf_counters->pkg_process_to_decrypt_ctr);
  unsigned long long pkg_process_to_checksum =
      atomic_load(&perf_counters->pkg_process_to_checksum);
  unsigned long long pkg_process_to_checksum_ctr =
      atomic_load(&perf_counters->pkg_process_to_checksum_ctr);
  unsigned long long pkg_process_to_l2_sw =
      atomic_load(&perf_counters->pkg_process_to_l2_sw);
  unsigned long long pkg_process_to_l2_sw_ctr =
      atomic_load(&perf_counters->pkg_process_to_l2_sw_ctr);
  unsigned long long pkg_process_to_counter =
      atomic_load(&perf_counters->pkg_process_to_counter);
  unsigned long long pkg_process_to_counter_ctr =
      atomic_load(&perf_counters->pkg_process_to_counter_ctr);
  unsigned long long pkg_process_to_checksum2 =
      atomic_load(&perf_counters->pkg_process_to_checksum2);
  unsigned long long pkg_process_to_checksum2_ctr =
      atomic_load(&perf_counters->pkg_process_to_checksum2_ctr);
  unsigned long long pkg_process_to_encrypt =
      atomic_load(&perf_counters->pkg_process_to_encrypt);
  unsigned long long pkg_process_to_encrypt_ctr =
      atomic_load(&perf_counters->pkg_process_to_encrypt_ctr);
  unsigned long long conf_sem_wait = atomic_load(&perf_counters->conf_sem_wait);
  unsigned long long conf_sem_wait_ctr =
      atomic_load(&perf_counters->conf_sem_wait_ctr);
  unsigned long long tap_write =
      atomic_load(&perf_counters->tap_write);
  unsigned long long tap_write_ctr =
      atomic_load(&perf_counters->tap_write_ctr);
  unsigned long long tap_read =
      atomic_load(&perf_counters->tap_read);
  unsigned long long tap_read_ctr =
      atomic_load(&perf_counters->tap_read_ctr);
  unsigned long long tcp_write =
      atomic_load(&perf_counters->tcp_write);
  unsigned long long tcp_write_ctr =
      atomic_load(&perf_counters->tcp_write_ctr);
  unsigned long long tcp_read =
      atomic_load(&perf_counters->tcp_read);
  unsigned long long tcp_read_ctr =
      atomic_load(&perf_counters->tcp_read_ctr);

  char timestr[STRTIME_SIZE];
  time_t now = time(NULL);
  struct tm now_tm;
  localtime_r(&now, &now_tm);
  strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", &now_tm);

  fprintf(f, "%s\n", timestr);

  double d = (double)enqueue / (double)enqueue_ctr;
  fprintf(f, "enqueue: %f ns\n", d);

  d = (double)decrypt / (double)decrypt_ctr;
  fprintf(f, "decrypt: %f ns\n", d);

  d = (double)checksum / (double)checksum_ctr;
  fprintf(f, "checksum: %f ns\n", d);

  d = (double)l2_sw / (double)l2_sw_ctr;
  fprintf(f, "l2 sw: %f ns\n", d);

  d = (double)counter / (double)counter_ctr;
  fprintf(f, "counter: %f ns\n", d);

  d = (double)checksum2 / (double)checksum2_ctr;
  fprintf(f, "checksum2: %f ns\n", d);

  d = (double)encrypt / (double)encrypt_ctr;
  fprintf(f, "encrypt: %f ns\n", d);

  d = (double)tcp_dequeue / (double)tcp_dequeue_ctr;
  fprintf(f, "tcp dqueue: %f ns\n", d);

  d = (double)tcp_send / (double)tcp_send_ctr;
  fprintf(f, "tcp send: %f ns\n", d);

  d = (double)pkg_process_to_decrypt / (double)pkg_process_to_decrypt_ctr;
  fprintf(f, "pkg process to decrypt: %f ns\n", d);

  d = (double)pkg_process_to_checksum / (double)pkg_process_to_checksum_ctr;
  fprintf(f, "pkg process to checksum: %f ns\n", d);

  d = (double)pkg_process_to_l2_sw / (double)pkg_process_to_l2_sw_ctr;
  fprintf(f, "pkg process to l2 sw: %f ns\n", d);

  d = (double)pkg_process_to_counter / (double)pkg_process_to_counter_ctr;
  fprintf(f, "pkg process to counter: %f ns\n", d);

  d = (double)pkg_process_to_checksum2 / (double)pkg_process_to_checksum2_ctr;
  fprintf(f, "pkg process to checksum2: %f ns\n", d);

  d = (double)pkg_process_to_encrypt / (double)pkg_process_to_encrypt_ctr;
  fprintf(f, "pkg process to encrypt: %f ns\n", d);

  d = (double)pkg_process / (double)pkg_process_ctr;
  fprintf(f, "pkg process: %f ns\n", d);

  d = (double)conf_sem_wait / (double)conf_sem_wait_ctr;
  fprintf(f, "config sem wait: %f ns\n", d);

  d = (double)tap_read / (double)tap_read_ctr;
  fprintf(f, "TAP read: %f ns\n", d);

  d = (double)tap_write / (double)tap_write_ctr;
  fprintf(f, "TAP write: %f ns\n", d);

  d = (double)tcp_read / (double)tcp_read_ctr;
  fprintf(f, "TCP read: %f ns\n", d);

  d = (double)tcp_write / (double)tcp_write_ctr;
  fprintf(f, "TCP write: %f ns\n", d);

  fprintf(f, "main queue fill: %f %%\n\n", queue_fill * 100.);

  fclose(f);
}

#endif
