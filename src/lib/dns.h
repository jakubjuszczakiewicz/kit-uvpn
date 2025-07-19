/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

typedef int (*dns_iterator)(const char * address, unsigned short port,
    void * data);

int dns_iterate_by_hostname(const char * hostname, unsigned short port,
    dns_iterator iterator, void * data);
