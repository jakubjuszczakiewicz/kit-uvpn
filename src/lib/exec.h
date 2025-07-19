/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <time.h>

void exec_with_env(const char * path, size_t env_count, char * envs);

int system_with_env(const char * path, size_t env_count, char * envs);

int proc_read_with_env(const char * path, size_t env_count, char * envs,
  char ** output_buffer, size_t * max_output_buffer_size,
  time_t max_exec_time_sec);
