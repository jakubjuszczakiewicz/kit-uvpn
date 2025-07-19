/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "clock.h"
#include <time.h>

uint64_t getnow_monotonic(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000000000LLU + tp.tv_nsec;
}

