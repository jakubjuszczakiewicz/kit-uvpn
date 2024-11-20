/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>

#ifndef MEMLOG

#define int_malloc(size) malloc(size)
#define int_calloc(size, numb) calloc(size, numb)
#define int_realloc(ptr, size) realloc(ptr, size)
#define int_free(ptr) free(ptr)

#define int_strdup(ptr) strdup(ptr)

#else

#define int_malloc(size) iint_malloc(size, __LINE__)
#define int_calloc(size, numb) iint_calloc(size, numb, __LINE__)
#define int_realloc(ptr, size) iint_realloc(ptr, size, __LINE__)
#define int_free(ptr) iint_free(ptr)

#define int_strdup(ptr) iint_strdup(ptr, __LINE__)

void * iint_malloc(size_t size, unsigned int line);
void * iint_calloc(size_t size, size_t numb, unsigned int line);
void * iint_realloc(void * old, size_t size, unsigned int line);
void iint_free(void * ptr);

char * iint_strdup(const char * ptr, unsigned int line);

#endif


