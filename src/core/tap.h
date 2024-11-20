/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __TAP_H__
#define __TAP_H__

#include "global.h"

void tap_init(struct tap_conn_info * conn, int * dev_sock, conn_id_t conn_id);
void tap_done(struct tap_conn_info * conn);
void tap_worker(struct tap_conn_info * conn, void * data, size_t data_size);

#endif
