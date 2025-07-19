/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

int logger_init(const char * path, unsigned int log_level);
int logger_reopen(void);
void logger_close(void);

void logger_printf(unsigned int log_level, const char * format, ...);
