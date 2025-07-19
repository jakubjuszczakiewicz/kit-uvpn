/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include "global.h"
#include "config.h"

extern struct tap_conn_info tap_conn;
extern struct tcp_conn_info * tcp_conn;

void tcp_activate_conn(conn_id_t src, conn_id_t dst, int activate);

struct static_servers_config_t * tcp_find_server_by_name(
    const char * name);

int is_connected(const char * name);
int is_connected_int(const char * name);

int add_tcp_conn(struct tcp_conn_desc_t new_conn,
    struct static_servers_config_t * config, const char * ipstr,
    unsigned short port, unsigned int tcp_flags);

void rem_tcp_conn(conn_id_t old_conn);

void conns_manager_thread(void *);
