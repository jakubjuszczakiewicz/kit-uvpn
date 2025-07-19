/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include "global.h"

int cipher_mode_str_to_int(const char * cipher);

size_t get_key_size(int cipher);

int checksum_str_to_int(const char * checksum);

size_t get_checksum_size(int checksum);

size_t get_checksum_hmac_key_size(int checksum);

int dict_alg_str_to_int(const char * dict_alg);

int conn_mode_str_to_int(const char * mode);

const char * conn_status_flag_to_str(unsigned int flags);

int queue_layout_str_to_int(const char * queue_layout);
