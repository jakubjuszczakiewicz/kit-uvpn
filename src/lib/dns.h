/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __DNS_H__
#define __DNS_H__

typedef int (*dns_iterator)(const char * address, unsigned short port,
    void * data);

int dns_iterate_by_hostname(const char * hostname, unsigned short port,
    dns_iterator iterator, void * data);

#endif
