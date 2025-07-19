/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

int tap_create(char * dev, int * fds, unsigned int count);
int tap_destroy(int * tap, unsigned int count);
int tap_read(int tap, void * buffer, unsigned int * buffer_size);
int tap_write(int tap, void * buffer, unsigned int buffer_size);
