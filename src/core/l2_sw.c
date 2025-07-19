/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "l2_sw.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "connection.h"
#include <avl.h>
#include <hashdict.h>
#include <clock.h>
#include <logger.h>
#include <threads.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#define MAC_TABLE_SIZE_16 (1024 * 64)
#define MAC_TABLE_SIZE_24 (1024 * 1024 * 16)

#define DICT_KEY_SIZE 8

#define MAX_REHASH 8

static void * g_mac_table = NULL;
static unsigned int max_arp_ttl = 900;

static int l2sw_algorithm = 0;

typedef struct mac_table
{
  conn_id_t conn_id;
  unsigned char mac_addr[DICT_KEY_SIZE];
  uint32_t pkt_idx;
  uint64_t last_active;
  conn_id_t bcast_idx;
  conn_id_t bcast_source;
} mac_table_t;

static int (*dict_set)(void * dict, void * data);
static int (*dict_get)(void * dict, void * data);
static void (*dict_delete)(void * dict, void * data);
static void (*dict_delete_if)(void * dict,
    int (*comparator)(const void *, const void *), void * data);
static void (*dict_iterate_callback)(void * dict,
    void (*callback)(void *, void *), void * callback_data);

static int comparator(const void * a, const void * b)
{
  const mac_table_t * first = (const mac_table_t *)a;
  const mac_table_t * second = (const mac_table_t *)b;

  return memcmp(first->mac_addr, second->mac_addr, DICT_KEY_SIZE);
}

static void * create_avl16(void)
{
  dict_set = (int (*)(void *, void *))avl_set;
  dict_get = (int (*)(void *, void *))avl_get;
  dict_delete = (void (*)(void *, void *))avl_delete;
  dict_delete_if = (void (*)(void *,
      int (*)(const void *, const void *), void *))avl_delete_if;
  dict_iterate_callback = (void (*)(void *, void (*)(void *, void *), void *))
      avl_iterate_callback;
  
  return avl_create(sizeof(mac_table_t), MAC_TABLE_SIZE_16, comparator);
}

static void * create_avl24(void)
{
  dict_set = (int (*)(void *, void *))avl_set;
  dict_get = (int (*)(void *, void *))avl_get;
  dict_delete = (void (*)(void *, void *))avl_delete;
  dict_delete_if = (void (*)(void *, 
      int (*)(const void *, const void *), void *))avl_delete_if;
  dict_iterate_callback = (void (*)(void *, void (*)(void *, void *), void *))
      avl_iterate_callback;

  return avl_create(sizeof(mac_table_t), MAC_TABLE_SIZE_24, comparator);
}

static void * create_hashtab16(void)
{
  dict_set = (int (*)(void *, void *))hashdict_set;
  dict_get = (int (*)(void *, void *))hashdict_get;
  dict_delete = (void (*)(void *, void *))hashdict_delete;
  dict_delete_if = (void (*)(void *, 
      int (*)(const void *, const void *), void *))hashdict_delete_if;
  dict_iterate_callback = (void (*)(void *, void (*)(void *, void *), void *))
      hashdict_iterate_callback;

  return hashdict_create(HASHDICT_16, sizeof(mac_table_t), DICT_KEY_SIZE,
      offsetof(struct mac_table, mac_addr), comparator, MAX_REHASH);
}

static void * create_hashtab24(void)
{
  dict_set = (int (*)(void *, void *))hashdict_set;
  dict_get = (int (*)(void *, void *))hashdict_get;
  dict_delete = (void (*)(void *, void *))hashdict_delete;
  dict_delete_if = (void (*)(void *, 
      int (*)(const void *, const void *), void *))hashdict_delete_if;
  dict_iterate_callback = (void (*)(void *, void (*)(void *, void *), void *))
      hashdict_iterate_callback;

  return hashdict_create(HASHDICT_24, sizeof(mac_table_t), DICT_KEY_SIZE,
      offsetof(struct mac_table, mac_addr), comparator, MAX_REHASH);
}

static void * create_dict(void)
{
  switch (l2sw_algorithm) {
    case DICT_ALGORITHM_AVL_16:
      return create_avl16();
    case DICT_ALGORITHM_AVL_24:
      return create_avl24();
    case DICT_ALGORITHM_HASHTAB_16:
      return create_hashtab16();
    case DICT_ALGORITHM_HASHTAB_24:
      return create_hashtab24();
    default:
      return NULL;
  }
}

static void dict_dispose(void * dict)
{
  switch (l2sw_algorithm) {
    case DICT_ALGORITHM_AVL_16:
      avl_dispose(dict);
      break;
    case DICT_ALGORITHM_AVL_24:
      avl_dispose(dict);
      break;
    case DICT_ALGORITHM_HASHTAB_16:
      hashdict_dispose(dict);
      break;
    case DICT_ALGORITHM_HASHTAB_24:
      hashdict_dispose(dict);
      break;
    default:
      break;
  }
}

static int del_comparator(const void * a, const void * b)
{
  const mac_table_t * first = (const mac_table_t *)a;
  const conn_id_t * second = (const conn_id_t *)b;

  return first->conn_id == *second;
}

static void exchange_conn_id(void * void_record, void * void_data)
{
  conn_id_t * conns = (conn_id_t *)void_data;
  mac_table_t * record = (mac_table_t *)void_record;

  if (record->conn_id == conns[0])
    record->conn_id = conns[1];
}

void l2_sw_init(unsigned int max_ttl, unsigned int algorithm)
{
  l2sw_algorithm = algorithm;
 
  g_mac_table = create_dict();

  max_arp_ttl = max_ttl;
}

void l2_sw_done(void)
{
  dict_dispose(g_mac_table);
}

void l2_sw_clear_arp(void)
{
  dict_dispose(g_mac_table);
  g_mac_table = create_dict();
}

void l2_sw_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

#ifdef PERF_COUNTERS
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();

    atomic_fetch_add(&perf_counters.pkg_process_to_l2_sw,
        time1 - data->perf_start);
    atomic_fetch_add(&perf_counters.pkg_process_to_l2_sw_ctr, 1);
  }
#endif

  if (data->msg_type == MSG_TYPE_CLOSE_CONN) {
    dict_delete_if(g_mac_table, del_comparator, &data->source);

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type == MSG_TYPE_CONN_DEACTIVATE) {
    conn_id_t conns[2] = { data->destination, data->source };
    dict_iterate_callback(g_mac_table, exchange_conn_id, conns);

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type == MSG_TYPE_CLEAR_ARP) {
    l2_sw_clear_arp();

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type != MSG_TYPE_RAW_NET) {
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if (data->net.packet_size == 0) {
    if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_BACKUP_FREEZE)
      data->destination = data->source;
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if ((be16toh(data->net.type) == PKT_TYPE_ETHERNET_PASSWORD) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_PASSWORD) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_SESSID) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_SESSID) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_EXTRA_INFO) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_EXTRA_INFO) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_BACKUP_FREEZE) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE)) {
    data->destination = data->source;
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  if ((be16toh(data->net.type) == PKT_TYPE_ETHERNET_PING) ||
      (be16toh(data->net.type) == PKT_TYPE_ETHERNET_PONG)) {
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  mac_table_t mac_entry;

  uint16_t vlan, eth_proto = (data->net.ethframe.proto[0] << 8) |
      data->net.ethframe.proto[1];
  if (eth_proto != VLAN_PROTO_ID)
    vlan = 0;
  else
    vlan = ((data->net.ethframe.proto[2] << 8) | data->net.ethframe.proto[3]) &
        0x0FFF;

  mac_entry.conn_id = -1;
  mac_entry.pkt_idx = htobe32(data->net.pkt_idx);
  memcpy(mac_entry.mac_addr, data->net.ethframe.src_mac, 6);
  memcpy(mac_entry.mac_addr + 6, &vlan, 2);

  if (!dict_get(g_mac_table, &mac_entry)) {
    mac_entry.conn_id = data->source;
    mac_entry.last_active = data->live_start;
    mac_entry.bcast_idx = data->net.bcast_idx;
    mac_entry.bcast_source = data->source;
    dict_set(g_mac_table, &mac_entry);

    if (data->destination != -1) {
#ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
        atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
      }
#endif
      return;
    }
  } else if (data->destination != -1) {
    if (!((mac_entry.pkt_idx < htobe32(data->net.pkt_idx)) ||
        (((htobe32(data->net.pkt_idx) & 0xC0000000) == 0) &&
        ((mac_entry.pkt_idx & 0xC0000000) > 0)))) {
      if (!((mac_entry.pkt_idx == htobe32(data->net.pkt_idx)) &&
          (mac_entry.bcast_idx < data->net.bcast_idx) &&
          (mac_entry.bcast_source == data->source))) {
        if (mac_entry.last_active + max_arp_ttl * 1000000000LLU <
            getnow_monotonic()) {
          dict_delete(g_mac_table, &mac_entry);

          logger_printf(LOGGER_ERROR, "Delete all entries for packet from"
              " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (%hu)",
              data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
              data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
              data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
              vlan, data->source);
          data->msg_type = MSG_TYPE_DROP;
        } else {
          data->msg_type = MSG_TYPE_DROP;

          logger_printf(LOGGER_DEBUG, "Drop duplicated packet from"
              " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (%hu)"
              " to %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (%hu)",
              data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
              data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
              data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
              vlan, data->source,
              data->net.ethframe.dst_mac[0], data->net.ethframe.dst_mac[1],
              data->net.ethframe.dst_mac[2], data->net.ethframe.dst_mac[3],
              data->net.ethframe.dst_mac[4], data->net.ethframe.dst_mac[5],
              data->destination);
#ifdef PERF_COUNTERS
          if (perf_counters.interval > 0) {
            time2 = getnow_monotonic();
            atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
            atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
          }
#endif
        }
        return;
      }
    }

    mac_entry.conn_id = data->source;
    mac_entry.pkt_idx = htobe32(data->net.pkt_idx);
    mac_entry.bcast_idx = data->net.bcast_idx;
    mac_entry.bcast_source = data->source;
    mac_entry.last_active = data->live_start;
    dict_set(g_mac_table, &mac_entry);

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
      atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
    }
#endif
    return;
  }

  mac_entry.last_active = data->live_start;
  mac_entry.conn_id = data->source;
  mac_entry.bcast_idx = data->net.bcast_idx;
  mac_entry.bcast_source = data->source;
  dict_set(g_mac_table, &mac_entry);

  mac_entry.conn_id = -1;
  memcpy(mac_entry.mac_addr, data->net.ethframe.dst_mac, 6);
  memcpy(mac_entry.mac_addr + 6, &vlan, 2);

  if (!dict_get(g_mac_table, &mac_entry)) {
    logger_printf(LOGGER_DEBUG, "Drop packet for unknown destination "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (%hd) (L2SW)",
        data->net.ethframe.dst_mac[0], data->net.ethframe.dst_mac[1],
        data->net.ethframe.dst_mac[2], data->net.ethframe.dst_mac[3],
        data->net.ethframe.dst_mac[4], data->net.ethframe.dst_mac[5],
        vlan, data->destination);
    data->msg_type = MSG_TYPE_DROP;
  } else if (data->source == mac_entry.conn_id) {
    logger_printf(LOGGER_DEBUG, "Loop detected for "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (L2SW)",
        data->net.ethframe.dst_mac[0], data->net.ethframe.dst_mac[1],
        data->net.ethframe.dst_mac[2], data->net.ethframe.dst_mac[3],
        data->net.ethframe.dst_mac[4], data->net.ethframe.dst_mac[5], vlan);
    dict_delete(g_mac_table, &mac_entry);
    data->destination = mac_entry.conn_id;
  } else {
    data->destination = mac_entry.conn_id;
  }

#ifdef PERF_COUNTERS
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.l2_sw, time2 - time1);
    atomic_fetch_add(&perf_counters.l2_sw_ctr, 1);
  }
#endif
}
