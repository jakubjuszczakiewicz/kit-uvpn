/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "hashdict.h"
#include <stdlib.h>
#include <string.h>
#include "tabhash.h"
#include "memlog.h"

#define DATA_OFFSET (sizeof(size_t))

struct hashdict_t
{
  void (*tabhash_reinit)(void * tabhash);
  uint32_t (*tabhash_hash)(const void * tabhash, const uint8_t * input);
  void (*tabhash_dispose)(void * tabhash);
  void * tabhash_t1;
  void * tabhash_t2;

  size_t data_size, data_step, key_size, key_offset, tab_size, tab_max_loop;
  unsigned int max_rehash;
  hashdict_comparator_t comparator;
  enum hashdict_size_e hashdict_size;

  uint8_t * T1;
  uint8_t * T2;
};

hashdict_t hashdict_create(enum hashdict_size_e hashdict_size, size_t data_size,
    size_t key_size, size_t key_offset, hashdict_comparator_t comparator,
    unsigned int max_rehash)
{
  size_t tab_size;
  void (*tabhash_reinit)(void * tabhash);
  uint32_t (*tabhash_hash)(const void * tabhash, const uint8_t * input);
  void (*tabhash_dispose)(void * tabhash);
  void * tabhash_t1;
  void * tabhash_t2;
  size_t tab_max_loop;

  switch (hashdict_size) {
    case HASHDICT_16:
      tab_size = 65536;
      tab_max_loop = 256 * 4;
      tabhash_t1 = tabhash16_create(key_size);
      tabhash_t2 = tabhash16_create(key_size);
      tabhash_reinit = (void (*)(void *))tabhash16_reinit;
      tabhash_hash =
          (uint32_t (*)(const void *, const uint8_t *))tabhash16_hash;
      tabhash_dispose = (void (*)(void *))tabhash16_dispose;
      break;
    case HASHDICT_24:
      tab_size = 16777216;
      tab_max_loop = 4096 * 4;
      tabhash_t1 = tabhash24_create(key_size);
      tabhash_t2 = tabhash24_create(key_size);
      tabhash_reinit = (void (*)(void *))tabhash24_reinit;
      tabhash_hash =
          (uint32_t (*)(const void *, const uint8_t *))tabhash24_hash;
      tabhash_dispose = (void (*)(void *))tabhash24_dispose;
      break;
    default:
      return NULL;
  }

  hashdict_t result = int_malloc(sizeof(*result));
  result->data_step = (data_size + DATA_OFFSET + DATA_OFFSET - 1);
  result->data_step /= DATA_OFFSET;
  result->data_step += 1;
  result->data_step *= DATA_OFFSET;

  result->T1 = int_calloc(result->data_step, tab_size);
  result->T2 = int_calloc(result->data_step, tab_size);

  result->tabhash_reinit = tabhash_reinit;
  result->tabhash_hash = tabhash_hash;
  result->tabhash_dispose = tabhash_dispose;
  result->tabhash_t1 = tabhash_t1;
  result->tabhash_t2 = tabhash_t2;

  result->data_size = data_size;
  result->key_size = key_size;
  result->key_offset = key_offset;
  result->tab_size = tab_size;
  result->tab_max_loop = tab_max_loop;
  result->max_rehash = max_rehash;
  result->comparator = comparator;
  result->hashdict_size = hashdict_size;

  return result;
}

void hashdict_dispose(hashdict_t hashdict)
{
  hashdict->tabhash_dispose(hashdict->tabhash_t1);
  hashdict->tabhash_dispose(hashdict->tabhash_t2);
  int_free(hashdict->T1);
  int_free(hashdict->T2);
  int_free(hashdict);
}

static void swap_data(void * ptr1, void * ptr2, size_t size)
{
  uint8_t tmp[size];
  memcpy(tmp, ptr1, size);
  memcpy(ptr1, ptr2, size);
  memcpy(ptr2, tmp, size);
}

static int hashdict_set_int(hashdict_t hashdict, void * data, 
    uint8_t * last_rehash)
{
  uint8_t * ptr = data;

  uint32_t hash1 = hashdict->tabhash_hash(hashdict->tabhash_t1,
      &ptr[hashdict->key_offset]);

  uint8_t * t1_ptr = &hashdict->T1[(hashdict->data_step) * hash1];
  if (*t1_ptr == 0) {
    *t1_ptr = 1;
    memcpy(&t1_ptr[DATA_OFFSET], ptr, hashdict->data_size);
    return 1;
  }

  if (hashdict->comparator(ptr, &t1_ptr[DATA_OFFSET]) == 0) {
    memcpy(&t1_ptr[DATA_OFFSET], ptr, hashdict->data_size);
    return 1;
  }

  uint32_t hash2 = hashdict->tabhash_hash(hashdict->tabhash_t2,
      &ptr[hashdict->key_offset]);

  uint8_t * t2_ptr = &hashdict->T2[(hashdict->data_step) * hash2];
  if (*t2_ptr == 0) {
    *t2_ptr = 1;
    memcpy(&t2_ptr[DATA_OFFSET], ptr, hashdict->data_size);
  }
  if (hashdict->comparator(ptr, &t2_ptr[DATA_OFFSET]) == 0) {
    memcpy(&t2_ptr[DATA_OFFSET], ptr, hashdict->data_size);
    return 1;
  }

  uint8_t tmp2[hashdict->data_step], *tmp;
  if (last_rehash)
    tmp = last_rehash;
  else
    tmp = tmp2;
  memset(tmp, 0, DATA_OFFSET);
  tmp[0] = 1;
  memcpy(&tmp[DATA_OFFSET], data, hashdict->data_size);

  for (size_t i = 0; i < hashdict->tab_max_loop; i++) {
    hash1 = hashdict->tabhash_hash(hashdict->tabhash_t1,
      &tmp[hashdict->key_offset + DATA_OFFSET]);
    t1_ptr = &hashdict->T1[(hashdict->data_step) * hash1];

    swap_data(t1_ptr, tmp, hashdict->data_step);

    if (tmp[0] == 0)
      return 1;

    hash2 = hashdict->tabhash_hash(hashdict->tabhash_t2,
      &tmp[hashdict->key_offset + DATA_OFFSET]);
    t2_ptr = &hashdict->T2[(hashdict->data_step) * hash2];

    swap_data(t2_ptr, tmp, hashdict->data_step);

    if (tmp[0] == 0)
      return 1;
  }

  return 0;
}

static int hashdict_rehash_int(hashdict_t hashdict)
{
  hashdict_t new = hashdict_create(hashdict->hashdict_size, hashdict->data_size,
      hashdict->key_size, hashdict->key_offset, hashdict->comparator,
      hashdict->max_rehash);

 for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T1[(hashdict->data_step) * i];
    if (*ptr == 0)
      continue;

    if (hashdict_set_int(new, ptr + DATA_OFFSET, NULL) == 0) {
      hashdict_dispose(new);
      return 0;
    }
  }

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T2[(hashdict->data_step) * i];
    if (*ptr == 0)
      continue;

    if (hashdict_set_int(new, ptr + DATA_OFFSET, NULL) == 0) {
      hashdict_dispose(new);
      return 0;
    }
  }

  swap_data(new, hashdict, sizeof(*new));
  hashdict_dispose(new);

  return 1;
}

int hashdict_set(hashdict_t hashdict, void * data)
{
  uint8_t last_rehash[hashdict->data_step];
  int x = hashdict_set_int(hashdict, data, last_rehash);
  if (x != 0)
    return x;

  for (int i = 0; i < hashdict->max_rehash; i++) {
    if ((hashdict_rehash_int(hashdict) != 0) &&
        (hashdict_set_int(hashdict, &last_rehash[DATA_OFFSET], NULL) != 0) &&
        (hashdict_set_int(hashdict, data, NULL) != 0)) {
      return 1;
    }
  }

  return 0;
}

int hashdict_get(hashdict_t hashdict, void * data)
{
  uint8_t * ptr = data;

  uint32_t hash1 = hashdict->tabhash_hash(hashdict->tabhash_t1,
      &ptr[hashdict->key_offset]);

  uint8_t * t1_ptr = &hashdict->T1[(hashdict->data_step) * hash1];
  if ((*t1_ptr != 0) &&
      (hashdict->comparator(ptr, &t1_ptr[DATA_OFFSET]) == 0)) {
    memcpy(ptr, &t1_ptr[DATA_OFFSET], hashdict->data_size);
    return 1;
  }

  uint32_t hash2 = hashdict->tabhash_hash(hashdict->tabhash_t2,
      &ptr[hashdict->key_offset]);

  uint8_t * t2_ptr = &hashdict->T2[(hashdict->data_step) * hash2];
  if ((*t2_ptr != 0) &&
      (hashdict->comparator(ptr, &t2_ptr[DATA_OFFSET]) == 0)) {
    memcpy(ptr, &t2_ptr[DATA_OFFSET], hashdict->data_size);
    return 1;
  }

  return 0;
}

void hashdict_delete(hashdict_t hashdict, void * data)
{
  uint8_t * ptr = data;

  uint32_t hash1 = hashdict->tabhash_hash(hashdict->tabhash_t1,
      &ptr[hashdict->key_offset]);

  uint8_t * t1_ptr = &hashdict->T1[(hashdict->data_step) * hash1];
  if ((*t1_ptr != 0) &&
      (hashdict->comparator(ptr, &t1_ptr[DATA_OFFSET]) == 0)) {
    memset(t1_ptr, 0, hashdict->data_step);
    return;
  }

  uint32_t hash2 = hashdict->tabhash_hash(hashdict->tabhash_t2,
      &ptr[hashdict->key_offset]);

  uint8_t * t2_ptr = &hashdict->T2[(hashdict->data_step) * hash2];
  if ((*t2_ptr != 0) &&
      (hashdict->comparator(ptr, &t2_ptr[DATA_OFFSET]) == 0)) {
    memset(t2_ptr, 0, hashdict->data_step);
    return;
  }
}

void hashdict_delete_if(hashdict_t hashdict, hashdict_comparator_t comparator,
    void * data)
{
  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T1[(hashdict->data_step) * i];
    if ((*ptr != 0) && comparator(&ptr[DATA_OFFSET], data)) {
      memset(ptr, 0, hashdict->data_step);
    }
  }

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T2[(hashdict->data_step) * i];
    if ((*ptr != 0) && comparator(&ptr[DATA_OFFSET], data)) {
      memset(ptr, 0, hashdict->data_step);
    }
  }
}

void hashdict_delete_if_callback(hashdict_t hashdict,
    hashdict_comparator_t comparator, hashdict_comparator_callback_t callback,
    void * data, void * callback_data)
{
  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T1[(hashdict->data_step) * i];
    if ((*ptr != 0) && comparator(&ptr[DATA_OFFSET], data)) {
      callback(callback_data, &ptr[DATA_OFFSET]);
      memset(ptr, 0, hashdict->data_step);
    }
  }

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T2[(hashdict->data_step) * i];
    if ((*ptr != 0) && comparator(&ptr[DATA_OFFSET], data)) {
      callback(callback_data, &ptr[DATA_OFFSET]);
      memset(ptr, 0, hashdict->data_step);
    }
  }
}

void hashdict_iterate_callback(hashdict_t hashdict,
    void (*callback)(void *, void *), void * callback_data)
{
  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T1[(hashdict->data_step) * i];
    if (*ptr != 0) {
      callback(&ptr[DATA_OFFSET], callback_data);
    }
  }

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T2[(hashdict->data_step) * i];
    if (*ptr != 0) {
      callback(&ptr[DATA_OFFSET], callback_data);
    }
  }
}

size_t hashdict_size(hashdict_t hashdict)
{
  size_t result = 0;

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T1[(hashdict->data_step) * i];
    if (*ptr != 0)
      result++;
  }

  for (uint32_t i = 0; i < hashdict->tab_size; i++) {
    uint8_t * ptr = &hashdict->T2[(hashdict->data_step) * i];
    if (*ptr != 0)
      result++;
  }

  return result;
}


