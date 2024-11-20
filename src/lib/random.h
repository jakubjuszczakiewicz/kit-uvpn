/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <stddef.h>

void random_init(void);
void random_done(void);

int random_bytes(size_t bytes, unsigned char * data);

#endif
