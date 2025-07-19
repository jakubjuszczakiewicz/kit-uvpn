/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap_int.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <clock.h>
#include <limits.h>
#include <linux/if.h>

struct nm_desc * netmap_desc = NULL;
int netmap_fd = 0;
int tap_fd = 0;

int tap_create(char * dev, int * fds, unsigned int count)
{
  struct ifreq ifr;
  int fd, err;
  const char * tundev = "/dev/net/tun";

  if ((fd = open(tundev, O_RDWR)) < 0) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  if (strlen(dev) >= sizeof(ifr.ifr_name)) {
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
  } else {
    strcpy(ifr.ifr_name, dev);
  }

  if (count < 2) {
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE | IFF_NAPI;

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
      close(fd);
      return err;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    *fds = fd;

    return 0;
  }

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_NAPI;
  int i;
  
  for (i = 0; i < count; i++) {
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
      goto err;
    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err) {
      close(fd);
      goto err;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      close(fd);
      goto err;
    }

    fds[i] = fd;
  }
  return 0;

err:
  for (--i; i >= 0; i--)
    close(fds[i]);
  return err;
}

int tap_destroy(int * tap, unsigned int count)
{
  for (unsigned int i = 1; i < count; i++)
    close(tap[i]);
  return ioctl(*tap, TUNSETPERSIST, 0);
}

int tap_read(int tap, void * buffer, unsigned int * buffer_size)
{
  ssize_t r = read(tap, buffer, *buffer_size);

  if (r >= 0) {
    *buffer_size = r;
    return r;
  }

  *buffer_size = 0;
  return r;
}

int tap_write(int tap, void * buffer, unsigned int buffer_size)
{
  return write(tap, buffer, buffer_size);
}
