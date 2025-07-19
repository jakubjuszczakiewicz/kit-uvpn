/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct tabhash16_t * tabhash16_t;
typedef struct tabhash24_t * tabhash24_t;

tabhash16_t tabhash16_create(uint16_t input_size);
void tabhash16_dispose(tabhash16_t tabhash);
void tabhash16_reinit(tabhash16_t tabhash);
uint32_t tabhash16_hash(const tabhash16_t tabhash, const uint8_t * input);

tabhash24_t tabhash24_create(uint16_t input_size);
void tabhash24_dispose(tabhash24_t tabhash);
void tabhash24_reinit(tabhash24_t tabhash);
uint32_t tabhash24_hash(const tabhash24_t tabhash, const uint8_t * input);
