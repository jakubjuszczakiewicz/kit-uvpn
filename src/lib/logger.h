/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __LOGGER_H__
#define __LOGGER_H__

int logger_init(const char * path, unsigned int log_level);
int logger_reopen(void);
void logger_close(void);

void logger_printf(unsigned int log_level, const char * format, ...);

#endif
