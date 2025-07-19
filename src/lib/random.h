/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>

void random_init(void);
void random_done(void);

int random_bytes(size_t bytes, unsigned char * data);
