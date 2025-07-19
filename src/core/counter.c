/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "counter.h"
#include <string.h>
#include "conststr.h"
#include <logger.h>
#include <clock.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#define CTR_FLAG_INVALID       0
#define CTR_FLAG_VALID         1
#define CTR_FLAG_FROZEN        2
#define CTR_FLAG_BACKUP_FROZEN 3

typedef struct conn_entry
{
  conn_id_t conn;
  uint16_t flags;
  checksum_t checksum;
  encrypt_key_t key;
  uint16_t vlan_id;
  uint32_t vlan_mask[MAX_VLAN_ID / 32];
} conn_entry_t;

static conn_entry_t g_conn_table[MAX_CONNECTIONS];

void counter_init(void)
{
  memset(g_conn_table, 0, sizeof(g_conn_table));
}

void counter_done(void)
{
}

void counter_worker_new_conn(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->source != data->destination)
    return;
  if ((data->source & 0xFFFF) < 1)
    return;

  conn_entry_t * entry = &g_conn_table[CONN_ID_NUM(data->source)];
  entry->conn = data->source;
  entry->flags = CTR_FLAG_VALID;
  entry->checksum = data->conn.checksum;
  memcpy(&entry->key, &data->conn.encrypt_key, sizeof(entry->key));
  entry->vlan_id = data->conn.vlan_id;
  memcpy(&entry->vlan_mask, &data->conn.vlan_mask,
      sizeof(entry->vlan_mask));

  logger_printf(LOGGER_DEBUG, "New connection/unfreezing from %u vlan %u",
      data->source, entry->vlan_id);
}

void counter_worker_close_conn(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if ((data->source & 0xFFFF) < 1)
    return;

  conn_entry_t * entry = &g_conn_table[CONN_ID_NUM(data->source)];

  entry->conn = 0;
  entry->flags = CTR_FLAG_INVALID;
  memset(&entry->checksum, 0, sizeof(entry->checksum));
  memset(&entry->key, 0, sizeof(entry->key));

  logger_printf(LOGGER_DEBUG, "Closing connection from %u", data->source);
}

void counter_worker_freeze(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if ((data->source & 0xFFFF) < 1)
    return;

  conn_entry_t * entry = &g_conn_table[CONN_ID_NUM(data->source)];

  entry->conn = data->source;
  entry->flags = CTR_FLAG_FROZEN;

  logger_printf(LOGGER_DEBUG, "Start freezing packet from %u", data->source);
}

void counter_worker_raw_net(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if ((be16toh(data->net.type) == PKT_TYPE_ETHERNET_PASSWORD) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_SESSID) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_EXTRA_INFO))
    return;

  if ((data->destination < 1) || ((data->destination & 0xFFFF) < 1)) {
    return;
  }

  size_t idx = CONN_ID_NUM(data->destination);
  conn_entry_t * entry = &g_conn_table[idx];
  if (entry->conn != data->destination) {
    data->msg_type = MSG_TYPE_INVALID;
    return;
  }

  uint16_t vlan_id, eth_proto = (data->net.ethframe.proto[0] << 8) |
      data->net.ethframe.proto[1];
  if (eth_proto != VLAN_PROTO_ID)
    vlan_id = 0;
  else
    vlan_id = ((data->net.ethframe.proto[2] << 8) |
        data->net.ethframe.proto[3]) & 0x0FFF;

  if (vlan_id != 0) {
    size_t idx2 = CONN_ID_NUM(data->source);
    if (data->source != TAP_CONN_ID) {
      conn_entry_t * entry2 = &g_conn_table[idx2];
      if (((entry2->vlan_mask[vlan_id >> 5] >> (vlan_id & 0x1F)) & 1) == 0) {
        data->msg_type = MSG_TYPE_DROP;
        return;
      }
    }
  }

  if (((entry->vlan_mask[vlan_id >> 5] >> (vlan_id & 0x1F)) & 1) == 0) {
    if (vlan_id != entry->vlan_id) {
      data->msg_type = MSG_TYPE_DROP;
      return;
    }
  }

  int16_t diff = 0;
  if ((entry->vlan_id != 0) && (entry->vlan_id == vlan_id)) {
    data->net.vlan_opt = VLAN_OPT_REMOVE_OUTPUT;
    data->net.vlan_id = entry->vlan_id;
    diff = -4;
  }

  if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_BACKUP_FREEZE) {
    entry->flags = CTR_FLAG_BACKUP_FROZEN;
    logger_printf(LOGGER_DEBUG, "Start backup freezing packet to %08X",
          data->destination);
    return;
  }

  if (entry->flags == CTR_FLAG_INVALID) {
    data->msg_type = MSG_TYPE_INVALID;
    return;
  }

  if (entry->flags == CTR_FLAG_FROZEN) {
    logger_printf(LOGGER_DEBUG, "Drop packet for freezen destination"
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (counter)",
        data->net.ethframe.dst_mac[0], data->net.ethframe.dst_mac[1],
        data->net.ethframe.dst_mac[2], data->net.ethframe.dst_mac[3],
        data->net.ethframe.dst_mac[4], data->net.ethframe.dst_mac[5]);
    data->msg_type = MSG_TYPE_DROP;
    return;
  }

  if (entry->flags == CTR_FLAG_BACKUP_FROZEN) {
    logger_printf(LOGGER_DEBUG, "Drop packet for backup freezen destination"
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (counter)",
        data->net.ethframe.dst_mac[0], data->net.ethframe.dst_mac[1],
        data->net.ethframe.dst_mac[2], data->net.ethframe.dst_mac[3],
        data->net.ethframe.dst_mac[4], data->net.ethframe.dst_mac[5]);
    data->msg_type = MSG_TYPE_DROP;
    return;
  }

  uint16_t length = data->net.packet_size +
      get_checksum_size(entry->checksum.type) + diff;

  if ((data->net.checksum.type == entry->checksum.type) &&
      (data->net.checksum.type >= CHECKSUM_SHA224) &&
      (data->net.checksum.type <= CHECKSUM_SHA512) && (diff != 0)) {
    data->net.checksum.type |= 0x8000;
  } else {
    entry->checksum.u64 = htobe64(be64toh(entry->checksum.u64) + 1);
    memcpy(&data->net.checksum, &entry->checksum, sizeof(entry->checksum));
  }

  uint32_t blocks = BLOCK_SIZE(length);

  uint64_t key_step = blocks >> 4;
  uint64_t key[4];

  memcpy(key, entry->key.key, sizeof(key));
  memcpy(&data->net.key, &entry->key, sizeof(data->net.key));

  logger_printf(LOGGER_DEBUG, "Counter step: %llu", key_step);

  key[0] = be64toh(key[0]);
  key[1] = be64toh(key[1]);

  key[1] += key_step;
  if (key[1] < key_step)
    key[0]++;

  key[0] = htobe64(key[0]);
  key[1] = htobe64(key[1]);

  memcpy(entry->key.key, key, sizeof(key));
}

void counter_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

#ifdef PERF_COUNTERS 
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();

    atomic_fetch_add(&perf_counters.pkg_process_to_counter,
        time1 - data->perf_start);
    atomic_fetch_add(&perf_counters.pkg_process_to_counter_ctr, 1);
  }
#endif

  switch (data->msg_type) {
    case MSG_TYPE_NEW_CONN:
      counter_worker_new_conn(void_data, data_size);
      break;
    case MSG_TYPE_CLOSE_CONN:
      counter_worker_close_conn(void_data, data_size);
      break;
    case MSG_TYPE_FREEZE_CONN:
      counter_worker_freeze(void_data, data_size);
      break;
    case MSG_TYPE_RAW_NET:
      counter_worker_raw_net(void_data, data_size);
      break;
  }

#ifdef PERF_COUNTERS 
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.counter, time2 - time1);
    atomic_fetch_add(&perf_counters.counter_ctr, 1);
  }
#endif
}
