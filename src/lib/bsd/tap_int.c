/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap_int.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

int tap_create(char * dev, int * fds, unsigned int count)
{
  if (count != 1)
    return -1;

  if (strncmp(dev, "tap", 3) != 0)
    return -1;

  char tundev[16];
  snprintf(tundev, sizeof(tundev), "/dev/%s", dev);

  *fds = open(tundev, O_RDWR);
  if (*fds < 0)
    return -1;

  return 0;
}

int tap_destroy(int * tap, unsigned int count)
{
  return close(*tap);
}

int tap_read(int tap, void * buffer, unsigned int * buffer_size)
{
  ssize_t r = read(tap, buffer, *buffer_size);
  if (r >= 0)
    *buffer_size = r;
  else
    *buffer_size = 0;

  return r;
}

int tap_write(int tap, void * buffer, unsigned int buffer_size)
{
  int size = buffer_size;
  return write(tap, buffer, (size > 58) ? size : 58);
}
