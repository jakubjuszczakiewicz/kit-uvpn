/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap.h"
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include "connection.h"
#include <tap_int.h>
#include <threads.h>
#include <clock.h>
#include <logger.h>
#include <memlog.h>

#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

struct tap_write_params
{
  struct tap_conn_info * conn;
  size_t idx;
};

void tap_io_read(void * arg)
{
  struct tap_conn_info * conn = (struct tap_conn_info *)arg;

  struct packet_record buffer;
  buffer.msg_type = MSG_TYPE_RAW_NET;
  buffer.source = TAP_CONN_ID;
  memset(buffer.net.key.key, 0, sizeof(buffer.net.key.key));
  buffer.net.key.type = -1;
  memset(&buffer.net.checksum, 0, sizeof(buffer.net.checksum));
  buffer.net.type = htobe16(PKT_TYPE_ETHERNET_ETHFRAME);

  struct pollfd fd[TAP_QUEUES];
  for (size_t i = 0; i < TAP_QUEUES; i++) {
    fd[i].fd = conn->dev_sock[i];
    fd[i].events = POLLIN;
    fd[i].revents = 0;
  }

  logger_printf(LOGGER_DEBUG, "TAP IO read start");
  while (!end_now) {
    unsigned int buffer_size = sizeof(buffer.net) -
        offsetof(struct packet_record, net.ethframe.dst_mac);

    int r = poll(fd, TAP_QUEUES, 1000);
    if (r < 1)
      continue;

    for (size_t i = 0; i < TAP_QUEUES; i++)
    {
      if ((fd[i].revents & POLLIN) == 0)
        continue;

      {
  #ifdef PERF_COUNTERS
        uint64_t time1 = 0, time2;
        if (perf_counters.interval > 0)
          time1 = getnow_monotonic();
  #endif
        tap_read(conn->dev_sock[i], &buffer.net.ethframe.dst_mac,
              &buffer_size);
  #ifdef PERF_COUNTERS
        if (perf_counters.interval > 0) {
          time2 = getnow_monotonic();
          atomic_fetch_add(&perf_counters.tap_read, time2 - time1);
          atomic_fetch_add(&perf_counters.tap_read_ctr, 1);
        }
  #endif
      }
      if (buffer_size < 16) {
        logger_printf(LOGGER_ERROR, "Packet from TAP is to small %u",
            buffer_size);
        continue;
      }

      if (buffer_size > MAX_MTU) {
        logger_printf(LOGGER_ERROR, "Packet from TAP is to big %u",
            buffer_size);
        continue;
      }

      buffer.net.length = htobe16(buffer_size);
      buffer.net.packet_size = buffer_size;

      buffer_size = BLOCK_SIZE(buffer_size + CHECKSUM_SIZE_MAX);
      buffer_size += offsetof(struct packet_record, net.pkt_idx);

#ifdef PERF_COUNTERS
      uint64_t time1, time2;
      time1 = getnow_monotonic();
      buffer.perf_start = time1;
#else
      buffer.live_start = getnow_monotonic();
#endif

      if (((buffer.net.ethframe.proto[0] << 8) + buffer.net.ethframe.proto[1])
          == VLAN_PROTO_ID) {
        uint16_t vlan_id = ((buffer.net.ethframe.proto[2] << 8) +
            buffer.net.ethframe.proto[3]) & 0xFFF;
        if (vlan_id > MAX_VLAN_ID)
          continue;
        uint32_t t = (conn->vlan_mask[vlan_id >> 5] >> (vlan_id & 0x1F)) & 1;
        if (t == 0) {
          continue;
        }

        buffer.net.vlan_opt = VLAN_OPT_DO_NOTHING;
        buffer.net.vlan_id = vlan_id;
      } else {
        buffer.net.vlan_opt = VLAN_OPT_DO_NOTHING;
        buffer.net.vlan_id = 0;
      }
      if (!is_mcast(buffer.net.ethframe.dst_mac)) {
        buffer.destination = -1;
        buffer.net.pkt_idx = 0;
        buffer.net.bcast_idx = 0;

        while ((queue_enqueue(global_queue, &buffer, buffer_size,
            NEEDS_FREE_ENQUEUE, MAX_ENQUEUE_TIME_NS) ==
            QUEUE_STAT_TIMEOUT_WARNING) && (!end_now));
      } else {
        conn->bcast_counter++;
        if (!conn->bcast_counter)
          conn->bcast_counter++;
        buffer.net.pkt_idx = htobe32(conn->bcast_counter);

        i_rwlock_rdlock(&conns_sem);
        for (unsigned int i = 0; (i < MAX_CONNECTIONS - 1) && (!end_now); i++) {
          if (tcp_conn[i].flags == CONN_STATUS_FLAG_CONNECTED) {
            buffer.destination = tcp_conn[i].conn_id;
            buffer.net.bcast_idx = i + 1;
            while ((queue_enqueue(global_queue, &buffer, buffer_size,
                NEEDS_FREE_ENQUEUE, MAX_ENQUEUE_TIME_NS) == 
                QUEUE_STAT_TIMEOUT_WARNING) && (!end_now)) {
              i_rwlock_rdunlock(&conns_sem);
              i_rwlock_rdlock(&conns_sem);
            }
          }
        }
        i_rwlock_rdunlock(&conns_sem);
      }

  #ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.enqueue, time2 - time1);
        atomic_fetch_add(&perf_counters.enqueue_ctr, 1);
      }
  #endif
    }
  }
}

void tap_io_write(void * arg)
{
  struct tap_conn_info * conn = ((struct tap_write_params *)arg)->conn;
  size_t idx = ((struct tap_write_params *)arg)->idx;
  int_free(arg);

  while (!end_now) {
    if (sem_wait_int(&conn->write_sem[idx], NULL))
      break;

    while (!end_now) {
      if (atomic_load(&conn->buffer_fill[idx]) == 0)
        break;

      size_t end = conn->buffer_end[idx];
      size_t ptr_size = conn->buffer_size[idx * TAP_QUEUES + end];
      unsigned char * ptr =
            &conn->buffer[((idx * TAP_QUEUES) + end) * MAX_MTU];

#ifdef PERF_COUNTERS
      uint64_t time1 = 0, time2;
      if (perf_counters.interval > 0)
        time1 = getnow_monotonic();
#endif
      ssize_t w = tap_write(conn->dev_sock[idx], ptr, ptr_size);
#ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.tap_write, time2 - time1);
        atomic_fetch_add(&perf_counters.tap_write_ctr, 1);
      }
#endif

      conn->buffer_end[idx] = (conn->buffer_end[idx] + 1) % TAP_BUFFER_SIZE;
      atomic_fetch_sub(&conn->buffer_fill[idx], 1);

      if (w < 0)
        logger_printf(LOGGER_DEBUG, "TAP write failed %u %s", errno,
            strerror(errno));
    }
  }
}

void tap_init(struct tap_conn_info * conn, int * dev_sock, conn_id_t conn_id)
{
  memcpy(conn->dev_sock, dev_sock, sizeof(int) * TAP_QUEUES);
  conn->bcast_counter = -2;
  conn->next_buffer = 0;

  memset(conn->buffer_size, 0, sizeof(conn->buffer_size));
  memset((void *)conn->buffer_fill, 0, sizeof(conn->buffer_fill));
  memset(conn->buffer_start, 0, sizeof(conn->buffer_start));
  memset(conn->buffer_end, 0, sizeof(conn->buffer_end));

  for (size_t i = 0; i < TAP_QUEUES; i++) {
    sem_init(&conn->write_sem[i], 0, 0);
    atomic_store(&conn->buffer_fill[i], 0);

    struct tap_write_params * params = int_malloc(sizeof(*params));
    params->conn = conn;
    params->idx = i;
    conn->io_write_thread[i] = thread_new(tap_io_write, params);
  }

  conn->io_read_thread = thread_new(tap_io_read, conn);
  memcpy(conn->vlan_mask, config->tap_vlans, sizeof(conn->vlan_mask));
}

void tap_done(struct tap_conn_info * conn)
{
  if (conn->io_read_thread)
    thread_join(conn->io_read_thread);
  for (size_t i = 0; i < TAP_QUEUES; i++) {
    if (conn->io_write_thread[i]) {
      thread_join(conn->io_write_thread[i]);
      sem_destroy(&conn->write_sem[i]);
    }
  }
}

void tap_worker(struct tap_conn_info * conn, void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  size_t length = data->net.packet_size;

  size_t idx = conn->next_buffer;

  unsigned int buffer_fill;
  do {
    buffer_fill = atomic_load(&conn->buffer_fill[idx]);
  } while (buffer_fill == TAP_BUFFER_SIZE);

  size_t start = conn->buffer_start[idx];

  memcpy(&conn->buffer[((idx * TAP_QUEUES) + start) * MAX_MTU],
      &data->net.ethframe.dst_mac, length);
  conn->buffer_size[idx * TAP_QUEUES + start] = length;
  conn->buffer_start[idx] = (conn->buffer_start[idx] + 1) % TAP_BUFFER_SIZE;

  atomic_fetch_add(&conn->buffer_fill[idx], 1);
  buffer_fill = atomic_load(&conn->buffer_fill[idx]);

  if(buffer_fill < 2)
    sem_post(&conn->write_sem[idx]);

  conn->next_buffer = (conn->next_buffer + 1) % TAP_QUEUES;

#ifdef PERF_COUNTERS
  if (perf_counters.interval > 0) {
    uint64_t time2 = getnow_monotonic();
    uint64_t time1 = data->perf_start;
    atomic_fetch_add(&perf_counters.pkg_process, time2 - time1);
    atomic_fetch_add(&perf_counters.pkg_process_ctr, 1);
  }
#endif
}
