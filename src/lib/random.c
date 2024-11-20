/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "random.h"

#include <stdio.h>

void random_init(void)
{
}

void random_done(void)
{
}

int random_bytes(size_t bytes, unsigned char * data)
{
  FILE * f = fopen("/dev/urandom", "rb");
  if (!f)
    return 1;
  (void)fread(data, bytes, 1, f);
  fclose(f);
  return 0;
}

