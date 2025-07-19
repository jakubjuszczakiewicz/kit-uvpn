/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tabhash.h"
#include <stdlib.h>
#include "random.h"
#include "memlog.h"

struct tabhash16_t
{
  uint16_t input_size;
  uint16_t * tab;
};

struct tabhash24_t
{
  uint16_t input_size;
  uint32_t * tab;
};

tabhash16_t tabhash16_create(uint16_t input_size)
{
  tabhash16_t tabhash = int_malloc(sizeof(*tabhash));
  tabhash->input_size = input_size;
  tabhash->tab = int_malloc(sizeof(*tabhash->tab) * input_size * 256);

  tabhash16_reinit(tabhash);

  return tabhash;
}

void tabhash16_reinit(tabhash16_t tabhash)
{
  random_bytes(sizeof(*tabhash->tab) * tabhash->input_size * 256,
      (uint8_t *)tabhash->tab);
}

void tabhash16_dispose(tabhash16_t tabhash)
{
  int_free(tabhash->tab);
  int_free(tabhash);
}

uint32_t tabhash16_hash(const tabhash16_t tabhash, const uint8_t * input)
{
  uint16_t hash = 0;

  for (unsigned int i = 0; i < tabhash->input_size; i++)
    hash ^= tabhash->tab[i * 256 + input[i]];

  return hash;
}

tabhash24_t tabhash24_create(uint16_t input_size)
{
  tabhash24_t tabhash = int_malloc(sizeof(*tabhash));
  tabhash->input_size = input_size;
  tabhash->tab = int_malloc(sizeof(*tabhash->tab) * input_size * 256);

  tabhash24_reinit(tabhash);

  return tabhash;
}

void tabhash24_reinit(tabhash24_t tabhash)
{
  random_bytes(sizeof(*tabhash->tab) * tabhash->input_size * 256,
      (uint8_t *)tabhash->tab);
  for (unsigned int i = 0; i < tabhash->input_size * 256; i++)
    tabhash->tab[i] &= 0x00FFFFFF;
}

void tabhash24_dispose(tabhash24_t tabhash)
{
  int_free(tabhash->tab);
  int_free(tabhash);
}

uint32_t tabhash24_hash(const tabhash24_t tabhash, const uint8_t * input)
{
  uint32_t hash = 0;

  for (unsigned int i = 0; i < tabhash->input_size; i++)
    hash ^= tabhash->tab[i * 256 + input[i]];

  return hash;
}
