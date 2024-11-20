/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __TCP_H__
#define __TCP_H__

#include "global.h"
#include "config.h"
#include <tcpc.h>

void tcp_init(struct tcp_conn_info * info, tcp_conn_t conn, conn_id_t conn_id,
    const struct static_servers_config_t * config, const char * ipstr,
    unsigned short port, unsigned int flags);
void tcp_done(struct tcp_conn_info * info);
void tcp_ping(struct tcp_conn_info * data, int flag, uint32_t pkg_idx);
void tcp_worker(struct tcp_conn_info * info, void * data, size_t data_size);
void send_tcp_close(struct tcp_conn_info * info);
void tcp_sent_backup_freeze(conn_id_t conn_id, const char * name);

#endif
