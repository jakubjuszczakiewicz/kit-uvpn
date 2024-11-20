/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tcpc.h"

#include <stdio.h>
#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#define LISTEN_BACKLOG 8

tcp_conn_stat_t tcp_conn_listen(tcp_conn_t conn, const char * ip_str,
    unsigned short port)
{
  char addr[sizeof(struct sockaddr_in6) > sizeof(struct sockaddr_in) ?
      sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)];
  socklen_t addrlen = sizeof(addr);

  conn->sock = 0;

  int ipv = ipstr_to_sockaddr(ip_str, port, (struct sockaddr *)&addr, &addrlen);
  if (ipv == 0)
    return TCP_CONN_STAT_ERROR_INVALID_ADDRESS;

  conn->ipv = ipv;
  conn->sock = socket((ipv == 4) ? AF_INET : AF_INET6, SOCK_STREAM, 0);

  const int enable = 1;
  setsockopt(conn->sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

  if (bind(conn->sock, (struct sockaddr *)&addr, addrlen) < 0)
    return TCP_CONN_STAT_ERROR_BIND_FAILED;

  if (listen(conn->sock, LISTEN_BACKLOG) < 0)
    return TCP_CONN_STAT_ERROR_LISTEN_FAILED;

  return TCP_CONN_STAT_OK;
}

tcp_conn_stat_t tcp_conn_accept(tcp_conn_t conn, char * ip_str,
    unsigned short * port, tcp_conn_t new_conn)
{
  socklen_t addrlen;

  if (conn->ipv == 4) {
    struct sockaddr_in addr;
    addrlen = sizeof(addr);

    if ((new_conn->sock =
        accept(conn->sock, (struct sockaddr *)&addr, &addrlen)) < 0)
      return TCP_CONN_STAT_ERROR_ACCEPT_FAILED;
    new_conn->ipv = 4;
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, 64);
    *port = ntohs(addr.sin_port);
    return TCP_CONN_STAT_OK;
  } else if (conn->ipv == 6) {
    struct sockaddr_in6 addr;
    addrlen = sizeof(addr);

    if ((new_conn->sock =
        accept(conn->sock, (struct sockaddr *)&addr, &addrlen)) < 0)
      return TCP_CONN_STAT_ERROR_ACCEPT_FAILED;
    new_conn->ipv = 6;
    inet_ntop(AF_INET6, &addr.sin6_addr, ip_str, 64);
    *port = ntohs(addr.sin6_port);
    return TCP_CONN_STAT_OK;
  }

  return TCP_CONN_STAT_ERROR_INVALID_SOCKET;
}

tcp_conn_stat_t tcp_conn_connect(tcp_conn_t conn, const char * ip_str,
    unsigned short port)
{
  char addr[sizeof(struct sockaddr_in6) > sizeof(struct sockaddr_in) ?
      sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)];
  socklen_t addrlen = sizeof(addr);

  conn->sock = 0;

  int ipv = ipstr_to_sockaddr(ip_str, port, (struct sockaddr *)&addr, &addrlen);
  if (ipv == 0)
    return TCP_CONN_STAT_ERROR_INVALID_ADDRESS;

  conn->ipv = ipv;
  conn->sock = socket((ipv == 4) ? AF_INET : AF_INET6, SOCK_STREAM, 0);
  if (connect(conn->sock, (struct sockaddr *)&addr, addrlen) < 0)
    return TCP_CONN_STAT_ERROR_CONNECT_FAILED;

  return TCP_CONN_STAT_OK;
}

tcp_conn_stat_t tcp_conn_close(tcp_conn_t conn)
{
  if (conn->sock)
    close(conn->sock);
  return TCP_CONN_STAT_OK;
}

tcp_conn_stat_t tcp_conn_read(tcp_conn_t conn, void * output,
    tcp_conn_data_size_t * read_bytes)
{
  *read_bytes = read(conn->sock, output, *read_bytes);

  if (*read_bytes > 0)
    return TCP_CONN_STAT_OK;
  if (*read_bytes == 0)
    return TCP_CONN_STAT_ERROR_END_OF_STREAM;

  *read_bytes = 0;
  return TCP_CONN_STAT_ERROR_READ_ERROR;
}

tcp_conn_stat_t tcp_conn_write(tcp_conn_t conn, const void * output,
    tcp_conn_data_size_t * write_bytes)
{
  *write_bytes = write(conn->sock, output, *write_bytes);
  if (*write_bytes > 0)
    return TCP_CONN_STAT_OK;

  return TCP_CONN_STAT_ERROR_WRITE_ERROR;
}

unsigned int tcp_conn_get_mss(tcp_conn_t conn)
{
  unsigned int tcp_maxseg;
  socklen_t tcp_maxseg_len = sizeof(tcp_maxseg);
  if(getsockopt(conn->sock, IPPROTO_TCP, TCP_MAXSEG, &tcp_maxseg,
      &tcp_maxseg_len))
    return 0;

  return tcp_maxseg;
}
