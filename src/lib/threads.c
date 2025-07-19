/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "threads.h"

#include <stdlib.h>
#include <pthread.h>
#include "memlog.h"

void * thread_new(void (*function)(void *), void * arg)
{
  pthread_t * th = int_malloc(sizeof(*th));

  pthread_create(th, NULL, (void *(*)(void *))function, arg);

  return th;
}

void thread_join(void * thread)
{
  void * ret;
  pthread_join(*(pthread_t *)thread, &ret);
  int_free(thread);
}
