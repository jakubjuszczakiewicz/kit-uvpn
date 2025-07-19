/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

struct str_t
{
  char * str;
  size_t size;
};

int ipstr_to_sockaddr(const char * ip_str, unsigned short port,
    struct sockaddr * addr, socklen_t * addrlen);

void print_cat(struct str_t * str, const char * format, ...);
