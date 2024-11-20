/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __TAP_INT_H__
#define __TAP_INT_H__

int tap_create(char * dev, int * fds, unsigned int count);
int tap_destroy(int * tap, unsigned int count);
int tap_read(int tap, void * buffer, unsigned int * buffer_size);
int tap_write(int tap, void * buffer, unsigned int buffer_size);

#endif
