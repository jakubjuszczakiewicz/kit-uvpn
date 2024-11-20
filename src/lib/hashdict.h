/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __HASHDICT_C__
#define __HASHDICT_C__

#include <stddef.h>
#include <stdint.h>

typedef struct hashdict_t * hashdict_t;

typedef int (* hashdict_comparator_t)(const void *, const void *);
typedef void (* hashdict_comparator_callback_t)(void *, void *);

enum hashdict_size_e
{
  HASHDICT_16,
  HASHDICT_24,
};

hashdict_t hashdict_create(enum hashdict_size_e hashdict_size, size_t data_size,
    size_t key_size, size_t key_offset, hashdict_comparator_t comparator,
    unsigned int max_rehash);
void hashdict_dispose(hashdict_t hashdict);

int hashdict_set(hashdict_t hashdict, void * data);
int hashdict_get(hashdict_t hashdict, void * data);
void hashdict_delete(hashdict_t hashdict, void * data);
void hashdict_delete_if(hashdict_t hashdict, hashdict_comparator_t comparator,
    void * data);
void hashdict_delete_if_callback(hashdict_t hashdict,
    hashdict_comparator_t comparator, hashdict_comparator_callback_t callback,
    void * data, void * callback_data);

void hashdict_iterate_callback(hashdict_t hashdict,
    void (*callback)(void *, void *), void * callback_data);

size_t hashdict_size(hashdict_t hashdict);

#endif
