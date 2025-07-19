/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

void * thread_new(void (*function)(void *), void * arg);
void thread_join(void *);
