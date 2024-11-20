/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#define _GNU_SOURCE
#include "rwmutex.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <execinfo.h>
#include "../core/perf.h"
#include "clock.h"

extern volatile int end_now;

int sem_wait_int(sem_t * sem, volatile unsigned int * local_end_now)
{
#ifdef PERF_COUNTERS 
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();
  }
#endif
  while (!end_now) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    int r = sem_timedwait(sem, &ts);

    if (r == 0) {
#ifdef PERF_COUNTERS 
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.conf_sem_wait, time2 - time1);
        atomic_fetch_add(&perf_counters.conf_sem_wait_ctr, 1);
      }
#endif

      return 0;
    }
    if (local_end_now && *local_end_now)
      return -1;
    if (errno == ETIMEDOUT)
      continue;
    return r;
  }

  return -1;
}

void kit_rwlock_init(rwmutex_t * mtx)
{
  atomic_store(mtx, 0);
}

void kit_rwlock_wrlock(rwmutex_t * mtx)
{
  unsigned int i;
  i = atomic_load(mtx) & 0x0000FFFF;

  while (!atomic_compare_exchange_strong(mtx, &i, i | 0x10000000)) {
    i &= 0x0000FFFF;
  }

  while ((i = atomic_load(mtx)) & 0x0FFFFFFF) {
    if (i & 0x0FFF0000) {
      atomic_fetch_and(mtx, 0x0FFFFFFF);

      i = atomic_load(mtx) & 0x0000FFFF;

      while (!atomic_compare_exchange_strong(mtx, &i, i | 0x10000000)) {
        i &= 0x0000FFFF;
      }
    }
  }
}

void kit_rwlock_rdlock(rwmutex_t * mtx)
{
  unsigned int i = atomic_load(mtx);
  do {
    i &= 0xFFFF;
  } while (!atomic_compare_exchange_strong(mtx, &i, i + 1));
}

void kit_rwlock_rdunlock(rwmutex_t * mtx)
{
  atomic_fetch_sub(mtx, 1);
}

void kit_rwlock_wrunlock(rwmutex_t * mtx)
{
  atomic_fetch_and(mtx, 0x0FFFFFFF);
}

void kit_rwlock_switch_rd_wr(rwmutex_t * mtx)
{
  atomic_fetch_add(mtx, 0x10000);
  unsigned int i = atomic_load(mtx) & 0x0FFFFFFF;

  while (!atomic_compare_exchange_strong(mtx, &i, i | 0x10000000)) {
    i &= 0xFFFFFFF;
  }

  do {
    i = atomic_load(mtx);
  } while ((i & 0x0000FFFF) > ((i >> 16) & 0x0FFF));
}

void kit_rwlock_switch_wr_rd(rwmutex_t * mtx)
{
  atomic_fetch_sub(mtx, 0x10000);
  atomic_fetch_and(mtx, 0x0FFFFFFF);
}

#ifdef MUTEXLOG

#define BT_BUF_SIZE 128

static char * get_path(size_t ptr, uint32_t tid)
{
  char * path;
  asprintf(&path, "rwmutex/%08zX-%04X.mtx", ptr, tid);

  return path;
}

static void log_lock(void * ptr, unsigned int line, const char * spath,
  const char * func)
{
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  nptrs = backtrace(buffer, BT_BUF_SIZE);

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
      return;
  }

  char * path = get_path((size_t)ptr, gettid());
  FILE * f = fopen(path, "w");
  if (!f) {
    free(strings);
    free(path);
    return;
  }
  fprintf(f, "%s:%u %s (%08X)\n", spath, line, func, *(unsigned int *)ptr);

  for (int j = 0; j < nptrs; j++)
    fprintf(f, "%s\n", strings[j]);

  fclose(f);
  free(strings);
  free(path);
}

static void log_unlock(void * ptr)
{
  char * path = get_path((size_t)ptr, gettid());
  unlink(path);
  free(path);
}

void dbg_rwlock_init(rwmutex_t * mtx, int line, const char * file)
{
  return kit_rwlock_init(mtx);
}

void dbg_rwlock_wrlock(rwmutex_t * mtx, int line, const char * file)
{
  kit_rwlock_wrlock(mtx);
  log_lock(mtx, line, file, "dbg_rwlock_wrlock");
}

void dbg_rwlock_rdlock(rwmutex_t * mtx, int line, const char * file)
{
  kit_rwlock_rdlock(mtx);
  log_lock(mtx, line, file, "dbg_rwlock_rdlock");
}

void dbg_rwlock_rdunlock(rwmutex_t * mtx, int line, const char * file)
{
  log_unlock(mtx);
  kit_rwlock_rdunlock(mtx);
}

void dbg_rwlock_wrunlock(rwmutex_t * mtx, int line, const char * file)
{
  log_unlock(mtx);
  kit_rwlock_wrunlock(mtx);
}

void dbg_rwlock_switch_rd_wr(rwmutex_t * mtx, int line, const char * file)
{
  kit_rwlock_switch_rd_wr(mtx);
  log_lock(mtx, line, file, "dbg_rwlock_switch_rd_wr");
}

void dbg_rwlock_switch_wr_rd(rwmutex_t * mtx, int line, const char * file)
{
  kit_rwlock_switch_wr_rd(mtx);
  log_lock(mtx, line, file, "dbg_rwlock_switch_wr_rd");
}

#endif
