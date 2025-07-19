/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include "global.h"

void l2_sw_init(unsigned int max_ttl, unsigned int algorithm);
void l2_sw_done(void);
void l2_sw_worker(void * data, size_t data_size);
