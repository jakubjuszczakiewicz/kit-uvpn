/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "random.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <kitcryptoc/ung.h>
#include <kitcryptoc/sha2.h>
#include <semaphore.h>

static struct kit_ung_512 seeddata;
static sem_t seedsem;

void random_init(void)
{
  uint8_t seedbuf[64];
  FILE * f = fopen("/dev/urandom", "rb");
  if (!f) {
    (void)fread(seedbuf, 64, 1, f);
  } else {
    srand(time(NULL));
    for (size_t i = 0; i < 64; i++)
      seedbuf[i] = rand();
  }
  kit_ung_512_init(&seeddata, kit_sha512, seedbuf);
  sem_init(&seedsem, 0, 1);
}

void random_done(void)
{
  sem_close(&seedsem);
  kit_ung_512_finish(&seeddata);
}

int random_bytes(size_t bytes, unsigned char * data)
{
  sem_wait(&seedsem);
  kit_ung_512_next(&seeddata, data, bytes);
  sem_post(&seedsem);
  return 0;
}

