/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include "global.h"

void counter_init(void);
void counter_done(void);

void counter_worker(void * data, size_t data_size);
