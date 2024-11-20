/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __THREADS_H__
#define __THREADS_H__

void * thread_new(void (*function)(void *), void * arg);
void thread_join(void *);

#endif
