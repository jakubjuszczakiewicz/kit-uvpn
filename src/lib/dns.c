/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "dns.h"
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int dns_iterate_by_hostname(const char * hostname, unsigned short port,
    dns_iterator iterator, void * data)
{
  struct addrinfo *res, *result = NULL;
  int err = 0;
  char ip_addr[64] = "";

  err = getaddrinfo(hostname, NULL, NULL, &result);
  if (err || !result) {
    if (result)
      freeaddrinfo(result);
    return -1;
  }

  res = result;

  while(res) {
    if (res->ai_family == AF_INET6) {
      inet_ntop(res->ai_family,
          &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, ip_addr,
          sizeof(ip_addr));
    } else if (res->ai_family == AF_INET) {
      inet_ntop(res->ai_family,
          &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip_addr,
          sizeof(ip_addr));
    } else {
      res = res->ai_next;
      continue;
    }
    if (iterator(ip_addr, port, data)) {
      freeaddrinfo(result);
      return 1;
    }
    res = res->ai_next;
  }

  freeaddrinfo(result);

  return 0;
}
