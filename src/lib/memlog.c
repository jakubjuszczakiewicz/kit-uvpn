/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "memlog.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>

#define BT_BUF_SIZE 1024

#ifdef MEMLOG

static void log_call(char * str, size_t ptr)
{
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  
  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL)
      return;

  char path[64];
  snprintf(path, sizeof(path) - 1, "ptrs/0x%zx.txt", ptr);

  FILE * f = fopen(path, "w+");
  if (!f)
    return;

  fprintf(f, "%s\n", str);
  for (int j = 0; j < nptrs; j++)
      fprintf(f, "%s\n", strings[j]);
  fclose(f);

  free(strings);
}

void * iint_malloc(size_t size, unsigned int line)
{
  void * ptr = malloc(size);

  char name[64];
  snprintf(name, sizeof(name) - 1, "malloc @ %u", line);

  log_call(name, (size_t)ptr);
  return ptr;
}

void * iint_calloc(size_t size, size_t numb, unsigned int line)
{
  void * ptr = calloc(size, numb);

  char name[64];
  snprintf(name, sizeof(name) - 1, "calloc @ %u", line);

  log_call(name, (size_t)ptr);
  return ptr;
}

void * iint_realloc(void * old, size_t size, unsigned int line)
{
  char path[64];
  snprintf(path, sizeof(path) - 1, "ptrs/0x%zx.txt", (size_t)old);

  unlink(path);

  void * ptr = realloc(old, size);

  char name[64];
  snprintf(name, sizeof(name) - 1, "realloc @ %u", line);
  log_call(name, (size_t)ptr);

  return ptr;
}

void iint_free(void * ptr)
{
  char path[64];
  snprintf(path, sizeof(path) - 1, "ptrs/0x%zx.txt", (size_t)ptr);
  unlink(path);

  free(ptr);
}

char * iint_strdup(const char * str, unsigned int line)
{
  char * ptr = strdup(str);

  char name[64];
  snprintf(name, sizeof(name) - 1, "strdup @ %u", line);
  log_call(name, (size_t)ptr);

  return ptr;
}

#endif
