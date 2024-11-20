/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __L2_SW_H__
#define __L2_SW_H__

#include <stddef.h>
#include "global.h"

void l2_sw_init(unsigned int max_ttl, unsigned int algorithm);
void l2_sw_done(void);
void l2_sw_worker(void * data, size_t data_size);

#endif
