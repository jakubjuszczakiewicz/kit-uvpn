/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#define TCP_CONN_STAT_OK                    0
#define TCP_CONN_STAT_ERROR_INVALID_SOCKET  1
#define TCP_CONN_STAT_ERROR_INVALID_ADDRESS 2
#define TCP_CONN_STAT_ERROR_BIND_FAILED     3
#define TCP_CONN_STAT_ERROR_LISTEN_FAILED   4
#define TCP_CONN_STAT_ERROR_ACCEPT_FAILED   5
#define TCP_CONN_STAT_ERROR_CONNECT_FAILED  6
#define TCP_CONN_STAT_ERROR_END_OF_STREAM   7
#define TCP_CONN_STAT_ERROR_READ_ERROR      8
#define TCP_CONN_STAT_ERROR_WRITE_ERROR     9

typedef struct tcp_conn_desc_t {
  int sock;
  int ipv;
} * tcp_conn_t;

typedef unsigned int tcp_conn_stat_t;
typedef long tcp_conn_data_size_t;

tcp_conn_stat_t tcp_conn_listen(tcp_conn_t conn, const char * ip_str,
    unsigned short port);
tcp_conn_stat_t tcp_conn_accept(tcp_conn_t conn, char * ip_str,
    unsigned short * port, tcp_conn_t new_conn);

tcp_conn_stat_t tcp_conn_connect(tcp_conn_t conn, const char * ip_str,
    unsigned short port);

tcp_conn_stat_t tcp_conn_close(tcp_conn_t conn);

tcp_conn_stat_t tcp_conn_read(tcp_conn_t conn, void * output,
    tcp_conn_data_size_t * read_bytes);
tcp_conn_stat_t tcp_conn_write(tcp_conn_t conn, const void * output,
    tcp_conn_data_size_t * write_bytes);

unsigned int tcp_conn_get_mss(tcp_conn_t conn);

