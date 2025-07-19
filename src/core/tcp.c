/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tcp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <semaphore.h>
#include <poll.h>
#include <threads.h>
#include <errno.h>
#include <rsa.h>
#include <logger.h>
#include <random.h>
#include <sys/select.h>
#include "config.h"
#include "conststr.h"
#include "connection.h"
#include "version.h"
#include <exec.h>
#include <clock.h>
#include <memlog.h>
#include <kitcryptoc/twofish.h>
#include <kitcryptoc/aes.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#define DEFAULT_MSS 1460
#define WRITE_PART_MULT (32)
#define MAX_WRITE_PART (DEFAULT_MSS * WRITE_PART_MULT)
#define MSS_WRITE_PART(mss) (mss * WRITE_PART_MULT)
#define WRITE_PART(mss) \
    ((MSS_WRITE_PART(mss) > MAX_WRITE_PART)?MAX_WRITE_PART:MSS_WRITE_PART(mss))

#define TCP_READ_AUTH_TIMEOUT_SEC 5

#define SALT_SIZE 16

#define MAX_PASSWORD_RECV_EXTRA_TIME_SEC (5)
    
#define MAX_PASSWORD_VERIFY_TIME_SEC (2)

#define BSWAP64(x) ((((x) & 0xFF) << 56) | (((x) & 0xFF00) << 40) | \
    (((x) & 0xFF0000) << 24) | (((x) & 0xFF000000) << 8) | \
    (((x) >> 8) & 0xFF000000) | (((x) >> 24) & 0xFF0000) | \
    (((x) >> 40) & 0xFF00) | (((x) >> 56) & 0xFF))

#define STR_OFFS (offsetof(struct packet_record, net.pkt_idx))

#define TCP_FREEZE_STATUS_UNFREEZE      0
#define TCP_FREEZE_STATUS_DESYNC        1
#define TCP_FREEZE_STATUS_FRREZE        2
#define TCP_FREEZE_STATUS_UNFREEZE_WAIT 3

struct tcp_pass_data
{
  char env_buffer[512];
  size_t env_count;
  char * cmd;
  conn_id_t conn_id;
  uint64_t connection_number;
};

static int tcp_new_conn(struct tcp_conn_info * data, int force)
{
  struct packet_record record;
  record.msg_type = MSG_TYPE_NEW_CONN;
  record.source = data->conn_id;
  record.destination = data->conn_id;

  uint64_t key[4] = {be64toh(data->enc_key[0]), be64toh(data->enc_key[1]),
      BSWAP64(data->enc_key[2]), BSWAP64(data->enc_key[3])};
  key[1] += data->written_blocks;
  if (key[1] < data->written_blocks)
    key[0]++;

  key[0] = htobe64(key[0]);
  key[1] = htobe64(key[1]);

  memcpy(&record.conn.encrypt_key.key, key, sizeof(key));
  record.conn.encrypt_key.type = data->cipher;
  record.conn.checksum.type = data->checksum;
  memcpy(record.conn.checksum.key, data->hmac_out_key, MAX_CHECKSUM_KEY_BYTES);

  record.conn.vlan_id = data->vlan_id;
  memcpy(record.conn.vlan_mask, data->vlan_mask, sizeof(data->vlan_mask));

#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif

  logger_printf(LOGGER_DEBUG, "New connection key %s (%08X)", data->name,
      data->conn_id);

  size_t data_size = ((char *)&record.conn - (char *)&record +
      sizeof(record.conn));

  queue_stat_t status;
  while (((status = queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS)) == QUEUE_STAT_TIMEOUT_WARNING) && force);

  return status == QUEUE_STAT_OK;
}

void tcp_ping(struct tcp_conn_info * data, int flag, uint32_t pong)
{
  uint64_t now = getnow_monotonic() / 1000000000LLU;

  if (!flag) {
    if (now > data->last_read + data->timeout[1]) {
      logger_printf(LOGGER_ERROR, "Connection with %s timed out (%lld)."
          " Closing it.", data->name, now - data->last_read);
      send_tcp_close(data);
      return;
    }

    if (now < data->last_read + data->timeout[0])
      return;
  }

  if (data->flags == CONN_STATUS_FLAG_INACTIVE_BACKUP)
      tcp_new_conn(data, 1);

  struct packet_record record;
  record.msg_type = MSG_TYPE_RAW_NET;
  record.source = data->conn_id;
  record.destination = data->conn_id;
  memset(&record.net.key, 0, sizeof(record.net.key));
  random_bytes(sizeof(record.net.pkt_idx),
      (unsigned char *)&record.net.pkt_idx);
  record.net.type =
      htobe16(pong ? PKT_TYPE_ETHERNET_PONG : PKT_TYPE_ETHERNET_PING);
  record.net.length = htobe16(0);
  record.net.packet_size = 0;
  record.net.vlan_id = data->vlan_id;
  if (data->vlan_id > 0) {
    record.net.vlan_opt = VLAN_OPT_ADD_INPUT;
  } else {
    record.net.vlan_opt = VLAN_OPT_DO_NOTHING;
  }
  record.net.checksum.type = 0;
  memset(record.conn.checksum.key, 0, MAX_CHECKSUM_KEY_BYTES);

#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif
  uint16_t pkg_length = BLOCK_SIZE(record.net.length);

  size_t data_size = ((unsigned char *)&record.net.pkt_idx -
        (unsigned char *)&record) + pkg_length + CHECKSUM_SIZE_MAX;

  logger_printf(LOGGER_DEBUG, "Data transfer with %s timed out. Pinging it.",
      data->name);

  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
}

void tcp_password(conn_id_t conn_id, uint8_t pass_length, const char * password,
    uint16_t msg_type)
{
  struct packet_record record;
  record.msg_type = MSG_TYPE_RAW_NET;
  record.source = conn_id;
  record.destination = conn_id;
  memset(&record.net.key, 0, sizeof(record.net.key));
  record.net.packet_size = MAX_PASSWORD_LEN + 1;
  record.net.pkt_idx = 0;
  record.net.type = htobe16(msg_type);
  record.net.length = htobe16(MAX_PASSWORD_LEN + 1);
  record.net.checksum.type = 0;
  memset(record.conn.checksum.key, 0, MAX_CHECKSUM_KEY_BYTES);

#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif
  record.net.password.pass_length = pass_length;
  memcpy(record.net.password.pass_str, password, pass_length);

  uint16_t pkg_length = BLOCK_SIZE(MAX_PASSWORD_LEN + 1);

  size_t data_size = ((unsigned char *)&record.net.pkt_idx -
        (unsigned char *)&record) + pkg_length + CHECKSUM_SIZE_MAX;

  logger_printf(LOGGER_INFO, "Enqueue TCP password length %hhu", pass_length);

  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
}

void send_tcp_close_thread(void * void_rec)
{
  struct packet_record * record = (struct packet_record *)void_rec;

  size_t data_size = ((char *)&record->conn - (char *)record);

  while (queue_enqueue(global_queue, record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
  int_free(record);
}

void send_tcp_close(struct tcp_conn_info * info)
{
  if (info->end_now)
    return;

  intptr_t tmp = atomic_load(&info->close_thread);
  if (tmp)
    return;
  if (!atomic_compare_exchange_strong(&info->close_thread, &tmp, 1U))
    return;
  struct packet_record * record = int_malloc(sizeof(*record));

  record->msg_type = MSG_TYPE_CLOSE_CONN;
  record->source = info->conn_id;
  record->destination = info->conn_id;

  atomic_store(&info->close_thread,
      (intptr_t)thread_new(send_tcp_close_thread, record));

  logger_printf(LOGGER_INFO, "Sent TCP close messege for \"%s\"", info->name);
}

static struct RSA * tcp_find_rsa_by_name(const char * name)
{
  i_rwlock_rdlock(&conns_sem);

  const struct static_servers_config_t * server = tcp_find_server_by_name(name);
  if (!server) {
    i_rwlock_rdunlock(&conns_sem);
    logger_printf(LOGGER_ERROR, "Can't find config for server: %s", name);
    return NULL;
  }

  struct RSA * rsa = load_rsakey(server->public_key);
  if (!rsa) {
    logger_printf(LOGGER_ERROR, "Can't load public key from file: %s",
        server->public_key);
    i_rwlock_rdunlock(&conns_sem);
    return NULL;
  }
  i_rwlock_rdunlock(&conns_sem);
  return rsa;
}

static int tcp_io_read_auth_send(struct tcp_conn_info * data)
{
  unsigned char * local_buffer = int_malloc(AUTH_BUFFER_SIZE);
  unsigned char * local_buffer_2 = int_malloc(AUTH_BUFFER_SIZE);

  struct RSA * rsa_2nd = tcp_find_rsa_by_name(data->name);
  if (!rsa_2nd) {
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  size_t out_size = 0;
  size_t name_len = strlen(config->name);

  logger_printf(LOGGER_DEBUG, "Start auth with method %u",
      data->output_auth_method);

  if (data->output_auth_method < OUTPUT_AUTH_METHOD_4) {
    rsa_done(rsa_2nd);
    int_free(local_buffer);
    int_free(local_buffer_2);

    logger_printf(LOGGER_ERROR,
        "Try to auth with method unsupported method (%u)",
        data->output_auth_method);

    return 1;
  } else if ((data->output_auth_method >= OUTPUT_AUTH_METHOD_4) &&
      (data->output_auth_method <= OUTPUT_AUTH_METHOD_5)) {
    local_buffer[0] = name_len;
    strcpy((char *)&local_buffer[1], config->name);
    random_bytes(SALT_SIZE, &local_buffer[1 + name_len]);

    size_t len = rsa_process_out(thiz_rsa, 0, local_buffer,
        name_len + 1 + SALT_SIZE, &local_buffer_2[2 + name_len]);

    local_buffer_2[0] = data->output_auth_method;
    local_buffer_2[1] = name_len;
    memcpy(&local_buffer_2[2], config->name, name_len);
    len += name_len + 2;

    out_size = rsa_process_out(rsa_2nd, 1, local_buffer_2, len,
        &local_buffer[2]);
    local_buffer[0] = out_size >> 8;
    local_buffer[1] = out_size;

    out_size += 2;
  } else {
    logger_printf(LOGGER_ERROR,
        "Try to auth with method unsupported method (%u)",
        data->output_auth_method);

    rsa_done(rsa_2nd);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  size_t pos = 0;
  while (pos < out_size) {
    tcp_conn_data_size_t length = out_size - pos;
    tcp_conn_stat_t stat = tcp_conn_write(&data->tcp_conn,
        &local_buffer[pos], &length);
    if (stat != TCP_CONN_STAT_OK) {
      rsa_done(rsa_2nd);
      int_free(local_buffer);
      int_free(local_buffer_2);
      logger_printf(LOGGER_ERROR, "TCP write error (%u) %s", errno,
          strerror(errno));
      return 1;
    }
    pos += length;
  }

  rsa_done(rsa_2nd);
  int_free(local_buffer);
  int_free(local_buffer_2);

  return 0;
}

static int tcp_io_read_data(tcp_conn_t conn, unsigned char * buffer,
    size_t (*need_read)(const unsigned char * buffer, size_t fill, void *),
    void * cmp_data, time_t max_time, size_t * fill)
{
  size_t local_buffer_fill = 0;
  time_t start_time = time(NULL);
  size_t for_read;

  while ((for_read = need_read(buffer, local_buffer_fill, cmp_data))) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(conn->sock, &set);
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    int r = select(conn->sock + 1, &set, NULL, NULL, &timeout);
    if (r == 1) {
      tcp_conn_data_size_t length = for_read;
      tcp_conn_stat_t stat = tcp_conn_read(conn, buffer + local_buffer_fill,
          &length);
      if (stat != TCP_CONN_STAT_OK) {
        logger_printf(LOGGER_ERROR, "TCP read error during auth");
        return 1;
      }

      local_buffer_fill += length;
    } else if (time(NULL) > start_time + max_time) {
      return 2;
    }
  }

  *fill = local_buffer_fill;
  return 0;
}

static size_t tcp_io_need_read_rsa(const unsigned char * buffer, size_t fill,
    void * data)
{
  size_t * max_size = (size_t *)data;

  if (fill <= 2)
    return *max_size - fill;

  size_t size = ((buffer[0] << 8) | buffer[1]);

  if (size >= fill + 2)
    return size - (fill + 2);
  return 0;
}

static int tcp_io_read_auth_recv(struct tcp_conn_info * data)
{
  unsigned char * local_buffer = int_malloc(AUTH_BUFFER_SIZE);
  unsigned char * local_buffer_2 = int_malloc(AUTH_BUFFER_SIZE);
  size_t full_size = 0;
  size_t max_size = AUTH_BUFFER_SIZE;
  int x = 0;

  if (x = tcp_io_read_data(&data->tcp_conn, local_buffer, tcp_io_need_read_rsa,
      &max_size, TCP_READ_AUTH_TIMEOUT_SEC, &full_size)) {
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }
  full_size -= 2;

  size_t len2 = rsa_process_in(thiz_rsa, 0, &local_buffer[2], full_size,
      local_buffer_2);
  if (len2 < 3) {
    logger_printf(LOGGER_DEBUG, "Auth error - problem during decrypt (%zd)",
      len2);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }
  char clientname[MAX_CLIENT_NAME_LENGTH + 1];
  size_t salt_len = 0;

  if ((local_buffer_2[0] >= OUTPUT_AUTH_METHOD_4) &&
      (local_buffer_2[0] <= OUTPUT_AUTH_METHOD_5)) {
    salt_len = SALT_SIZE;
  } else {
    logger_printf(LOGGER_DEBUG, "Auth error - unsupported auth method (%d)",
      local_buffer_2[0]);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  if (local_buffer_2[1] > MAX_CLIENT_NAME_LENGTH + salt_len) {
    logger_printf(LOGGER_DEBUG, "Auth error - invalid client name length");
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }
  if (len2 < local_buffer_2[1] + salt_len + 1) {
    logger_printf(LOGGER_DEBUG, "Auth error - problem during decrypt (%zd, %u)",
      len2, local_buffer_2[1]);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  memset(clientname, 0, MAX_CLIENT_NAME_LENGTH + 1);
  memcpy(clientname, &local_buffer_2[2], local_buffer_2[1]);

  logger_printf(LOGGER_DEBUG, "Loocking for server \"%s\"", clientname);

  if (data->incomming && is_connected(clientname)) {
    logger_printf(LOGGER_ERROR, "Server \"%s\" already connected!", clientname);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  size_t i;

  i_rwlock_rdlock(&conns_sem);

  for (i = 0; i < config->static_servers_count; i++) {
    if (strcmp(config->static_servers[i].name, clientname) != 0)
      continue;

    if (!config->static_servers[i].public_key)
      continue;
    if (!config->static_servers[i].allow_new_connect)
      continue;
    if (conn_mode_str_to_int(config->static_servers[i].mode) ==
        CONN_MODE_REMOVED)
      continue;

    struct RSA * rsa = load_rsakey(config->static_servers[i].public_key);
    if (!rsa) {
      logger_printf(LOGGER_DEBUG, "Load RSA key error");
      continue;
    }

    size_t len = rsa_process_in(rsa, 1, &local_buffer_2[2 + local_buffer_2[1]],
        len2 - 2 - local_buffer_2[1], local_buffer);
    rsa_done(rsa);
    if (len <= salt_len) {
      logger_printf(LOGGER_DEBUG, "Auth error (2) %zu %zu", len, salt_len);
      continue;
    }

    len -= salt_len;
    if (len != strlen(config->static_servers[i].name) + 1) {
      logger_printf(LOGGER_DEBUG, "Auth error (3)");
      continue;
    }
    if (local_buffer_2[0] != config->static_servers[i].output_auth_method) {
      logger_printf(LOGGER_DEBUG, "Auth error (4) %d %d", local_buffer_2[0],
          config->static_servers[i].output_auth_method);
      continue;
    }

    size_t len2 = local_buffer[0];
    if (len2 + 1 != len) {
      logger_printf(LOGGER_DEBUG, "Auth error (5)");
      continue;
    }
    if (memcmp(&local_buffer[1], config->static_servers[i].name,
        len2) == 0)
      break;

    logger_printf(LOGGER_DEBUG, "Auth error (6)");
  }

  if (i == config->static_servers_count) {
    i_rwlock_rdunlock(&conns_sem);
    logger_printf(LOGGER_ERROR, "Auth error - server not found");
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }

  if (data->name[0]) {
    if (strcmp(data->name, config->static_servers[i].name)) {
      i_rwlock_rdunlock(&conns_sem);
      logger_printf(LOGGER_ERROR, "Auth error - invalid server name");
      int_free(local_buffer);
      int_free(local_buffer_2);
      return 1;
    }
  }
  strncpy(data->name, config->static_servers[i].name,
      MAX_CLIENT_NAME_LENGTH - 1);
  data->timeout[0] = config->static_servers[i].keepalive[0];
  data->timeout[1] = config->static_servers[i].keepalive[1];

  data->vlan_id = config->static_servers[i].vlan_id;
  memcpy(data->vlan_mask, config->static_servers[i].allowed_vlans,
      sizeof(data->vlan_mask));

  if (data->cipher < 0)
    data->cipher = cipher_mode_str_to_int(config->static_servers[i].cipher);
  if (data->checksum < 0)
    data->checksum = checksum_str_to_int(config->static_servers[i].checksum);
  if (data->cipher < 0) {
    logger_printf(LOGGER_DEBUG, "Auth error - invalid cipher (%s) for %s",
        config->static_servers[i].cipher, config->static_servers[i].name);
    i_rwlock_rdunlock(&conns_sem);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }
  if (data->checksum < 0) {
    logger_printf(LOGGER_DEBUG, "Auth error - invalid checksum (%s) for %s",
        config->static_servers[i].checksum, config->static_servers[i].name);
    i_rwlock_rdunlock(&conns_sem);
    int_free(local_buffer);
    int_free(local_buffer_2);
    return 1;
  }
  if (data->send_extra_info < 0) {
    data->send_extra_info = config->static_servers[i].send_extra_info;
  }

  logger_printf(LOGGER_INFO, "Auth success for server \"%s\"", data->name);

  if ((config->static_servers[i].limit_output_buffer_size !=
      data->limit_output_buffer_size) &&
      (config->static_servers[i].limit_output_buffer_size != 0)) {
    data->limit_output_buffer_size =
        config->static_servers[i].limit_output_buffer_size;
  } else if (data->limit_output_buffer_size == 0) {
    data->limit_output_buffer_size = MAX_BUFFER_SIZE;
  }
  if (data->limit_output_buffer_size < MIN_BUFFER_SIZE) {
    data->limit_output_buffer_size = MIN_BUFFER_SIZE;
  } else if (data->limit_output_buffer_size > MAX_BUFFER_SIZE) {
    data->limit_output_buffer_size = MAX_BUFFER_SIZE;
  }

  unsigned int flags = CONN_STATUS_FLAG_CONNECTED;
  if (conn_mode_str_to_int(config->static_servers[i].mode) ==
      CONN_MODE_ACTIVE_BACKUP) {
    for (size_t j = 0; j < config->static_servers_count; j++) {
      if (config->static_servers[j].backup &&
          (strcmp(config->static_servers[j].backup,
          config->static_servers[i].name) == 0)) {
        if (is_connected_int(config->static_servers[j].name)) {
          flags = CONN_STATUS_FLAG_INACTIVE;
          tcp_sent_backup_freeze(data->conn_id, data->name);
        }
      }
    }
  }

  if (data->output_auth_method < 0) {
    data->output_auth_method = config->static_servers[i].output_auth_method;
  }

  if (data->incomming) {
    if ((config->static_servers[i].password_verifier) &&
        (config->static_servers[i].password_verifier[0])) {
      flags = CONN_STATUS_FLAG_WAIT_RECV_PASS;
    }
  } else {
    if ((config->static_servers[i].password_injecter) &&
        (config->static_servers[i].password_injecter[0])) {
      flags = CONN_STATUS_FLAG_WAIT_SEND_PASS;
    }
  }

  if (config->static_servers[i].limit_output_chunk_size == 0) {
    data->mss = tcp_conn_get_mss(&data->tcp_conn);
    if (!data->mss)
      data->mss = DEFAULT_MSS;
  } else {
    data->mss = config->static_servers[i].limit_output_chunk_size;
  }

  config->static_servers[i].conn_id = data->conn_id;
  data->flags = flags;

  if ((config->static_servers[i].backup) &&
      (config->static_servers[i].backup[0])) {
    struct static_servers_config_t * backup = tcp_find_server_by_name(
        config->static_servers[i].backup);
    if (backup && (backup->conn_id > 0)) {
      int k = CONN_ID_NUM(backup->conn_id);
      if (tcp_conn[k].flags == CONN_STATUS_FLAG_CONNECTED) {
        tcp_activate_conn(data->conn_id, backup->conn_id, 0);
        tcp_sent_backup_freeze(backup->conn_id, backup->name);
      }
    }
  }

  i_rwlock_rdunlock(&conns_sem);
  int_free(local_buffer);
  int_free(local_buffer_2);
  return 0;
}

int tcp_io_read_key_send(struct tcp_conn_info * data)
{
  size_t enc_keysize = sizeof(uint64_t) * get_key_size(data->cipher);
  size_t key_size = enc_keysize + get_checksum_hmac_key_size(data->checksum);

  uint8_t key[MAX_CIPHER_KEY_SIZE + MAX_CHECKSUM_KEY_BYTES];
  if (random_bytes(key_size, (unsigned char *)key)) {
    return 1;
  }

  memcpy(data->enc_key, key, enc_keysize);
  memcpy(data->hmac_out_key, &key[enc_keysize],
      get_checksum_hmac_key_size(data->checksum));

  unsigned char local_buffer[AUTH_BUFFER_SIZE];
  unsigned char local_buffer_2[AUTH_BUFFER_SIZE];

  struct RSA * rsa_2nd = tcp_find_rsa_by_name(data->name);
  if (!rsa_2nd) {
    logger_printf(LOGGER_ERROR, "Key exchange - unable to find key for ",
        data->name);
    return 1;
  }

  size_t out_size;
  if (data->output_auth_method == OUTPUT_AUTH_METHOD_4) {
    out_size = rsa_process_out(rsa_2nd, 1, (unsigned char *)key,
        key_size, &local_buffer[2]);

    local_buffer[0] = out_size >> 8;
    local_buffer[1] = out_size;

    out_size += 2;
  } else if (data->output_auth_method == OUTPUT_AUTH_METHOD_5) {
    size_t len = rsa_process_out(thiz_rsa, 0, (unsigned char *)key,
        key_size, &local_buffer_2[2]);
    local_buffer_2[0] = len >> 8;
    local_buffer_2[1] = len;

    out_size = rsa_process_out(rsa_2nd, 1, local_buffer_2, len + 2,
        &local_buffer[2]);

    local_buffer[0] = out_size >> 8;
    local_buffer[1] = out_size;

    out_size += 2;
  } else {
    rsa_done(rsa_2nd);
    logger_printf(LOGGER_ERROR, "Key exchange - invalid auth method: %d",
        data->output_auth_method);
    return 1;
  }
  rsa_done(rsa_2nd);

  size_t pos = 0;
  while (pos < out_size) {
    tcp_conn_data_size_t length = out_size - pos;
    tcp_conn_stat_t stat = tcp_conn_write(&data->tcp_conn,
        &local_buffer[pos], &length);
    if (stat != TCP_CONN_STAT_OK) {
      logger_printf(LOGGER_ERROR, "TCP write error (%u) %s", errno,
          strerror(errno));
      return 1;
    }
    pos += length;
  }

  return 0;
}

int tcp_io_read_key_recv(struct tcp_conn_info * data)
{
  unsigned char local_buffer[AUTH_BUFFER_SIZE];
  unsigned char local_buffer_2[AUTH_BUFFER_SIZE];
  size_t full_size = 0;
  size_t max_size = AUTH_BUFFER_SIZE;
  size_t enc_keysize = sizeof(uint64_t) * get_key_size(data->cipher);
  size_t key_size = enc_keysize + get_checksum_hmac_key_size(data->checksum);

  if (tcp_io_read_data(&data->tcp_conn, local_buffer, tcp_io_need_read_rsa,
      &max_size, TCP_READ_AUTH_TIMEOUT_SEC, &full_size)) {
    logger_printf(LOGGER_ERROR, "Key exchange - invalid key read");
    return 1;
  }
  full_size -= 2;
  size_t len2;

  if (data->output_auth_method == OUTPUT_AUTH_METHOD_4) {
    len2 = rsa_process_in(thiz_rsa, 0, &local_buffer[2], full_size,
        local_buffer_2);

    if (len2 != key_size)
      return 1;

    memcpy(data->dec_key, local_buffer_2, enc_keysize);
    memcpy(data->hmac_in_key, &local_buffer_2[enc_keysize],
        get_checksum_hmac_key_size(data->checksum));
  } else if (data->output_auth_method == OUTPUT_AUTH_METHOD_5) {
    len2 = rsa_process_in(thiz_rsa, 0, &local_buffer[2], full_size,
        local_buffer_2);

    size_t next_size = (local_buffer_2[0] << 8) + local_buffer_2[1];
    if (next_size + 2 != len2) {
      logger_printf(LOGGER_ERROR,
          "Key exchange - invalid data size (1) %zd %zd", next_size + 2, len2);
      return 1;
    }

    struct RSA * rsa_2nd = tcp_find_rsa_by_name(data->name);
    if (!rsa_2nd) {
      logger_printf(LOGGER_ERROR, "Key exchange - unable to find key for ",
          data->name);
      return 1;
    }
    len2 = rsa_process_in(rsa_2nd, 1, &local_buffer_2[2], next_size,
        local_buffer);
    rsa_done(rsa_2nd);

    if (len2 != key_size) {
      logger_printf(LOGGER_ERROR,
          "Key exchange - invalid data size (2) %zd %zd", len2, key_size);
      return 1;
    }

    memcpy(data->dec_key, local_buffer, enc_keysize);
    memcpy(data->hmac_in_key, &local_buffer[enc_keysize],
        get_checksum_hmac_key_size(data->checksum));
  } else {
    logger_printf(LOGGER_ERROR, "Key exchange - invalid auth method: %d",
        data->output_auth_method);
    return 1;
  }

  return 0;
}

static void tcp_read_password(void * void_data)
{
  struct tcp_pass_data * data = (struct tcp_pass_data *)void_data;

  char * pass_buffer = NULL;
  size_t pass_buffer_size = MAX_PASSWORD_LEN;

  logger_printf(LOGGER_DEBUG, "Ask for password by cmd: \"%s\"", data->cmd);

  i_rwlock_rdlock(&conns_sem);

  uint64_t max_password_wait_time = config->max_password_wait_time;
  i_rwlock_rdunlock(&conns_sem);

  if (proc_read_with_env(data->cmd, data->env_count, data->env_buffer,
      &pass_buffer, &pass_buffer_size, max_password_wait_time) == 0) {
    i_rwlock_rdlock(&conns_sem);

    if ((data->conn_id) && 
        (data->conn_id == tcp_conn[CONN_ID_NUM(data->conn_id)].conn_id)) {
      tcp_password(data->conn_id, pass_buffer_size, pass_buffer,
          PKT_TYPE_ETHERNET_ENC_PASSWORD);

      tcp_conn[CONN_ID_NUM(data->conn_id)].flags =
          CONN_STATUS_FLAG_WAIT_VERIFY_PASS;
    }

    i_rwlock_rdunlock(&conns_sem);
    int_free(pass_buffer);
    int_free(data->cmd);
    int_free(data);
    return;
  }

  int_free(pass_buffer);
  int_free(data->cmd);
  int_free(data);
}

static void tcp_sent_extra_info(struct tcp_conn_info * data)
{
  struct packet_record record;
  memset(&record, 0, sizeof(record));

  record.msg_type = MSG_TYPE_RAW_NET;
  record.source = data->conn_id;
  record.destination = data->conn_id;
  memset(&record.net.key, 0, sizeof(record.net.key));
  record.net.packet_size = sizeof(record.net.extra_info);
  record.net.pkt_idx = 0;
  record.net.type = htobe16(PKT_TYPE_ETHERNET_ENC_EXTRA_INFO);
  record.net.length = htobe16(sizeof(record.net.extra_info));
  record.net.checksum.type = 0;
  memset(record.conn.checksum.key, 0, MAX_CHECKSUM_KEY_BYTES);

#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif
  record.net.extra_info.extra_info_struct_ver = EXTRA_INFO_STRUCT_VER_DEFAULT;
  memcpy(record.net.extra_info.uVPN_version_str, kit_uvpn_version_str,
      kit_uvpn_version_str_len);
  memset(record.net.extra_info.uVPN_version_str + kit_uvpn_version_str_len, 0,
         VERSION_STR_LEN - kit_uvpn_version_str_len);
  memcpy(record.net.extra_info.cryptolib_name_str, cryptolib_name_str,
      LIB_NAME_STR_LEN);
  memcpy(record.net.extra_info.cryptolib_version_str, cryptolib_version_str,
      VERSION_STR_LEN);
  memcpy(record.net.extra_info.os_name_str, os_name_str, OS_NAME_STR_LEN);
  memcpy(record.net.extra_info.compilation_time_str, compilation_time_str,
      COMPILATIION_TIME_STR_LEN);

  uint16_t pkg_length = BLOCK_SIZE(record.net.packet_size);

  size_t data_size = ((unsigned char *)&record.net.pkt_idx -
        (unsigned char *)&record) + pkg_length + CHECKSUM_SIZE_MAX;

  logger_printf(LOGGER_INFO, "Sending extra info to \"%s\"", data->name);

  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
}

void tcp_sent_backup_freeze(conn_id_t conn_id, const char * name)
{
  struct packet_record record;
  memset(&record, 0, sizeof(record));

  record.msg_type = MSG_TYPE_RAW_NET;
  record.source = conn_id;
  record.destination = conn_id;
  memset(&record.net.key, 0, sizeof(record.net.key));
  record.net.packet_size = 0;
  random_bytes(sizeof(record.net.pkt_idx),
      (unsigned char *)&record.net.pkt_idx);
  record.net.type = htobe16(PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE);
  record.net.length = 0;
  record.net.checksum.type = 0;
  memset(record.conn.checksum.key, 0, MAX_CHECKSUM_KEY_BYTES);

#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif

  uint16_t pkg_length = BLOCK_SIZE(record.net.packet_size);

  size_t data_size = ((unsigned char *)&record.net.pkt_idx -
        (unsigned char *)&record) + pkg_length + CHECKSUM_SIZE_MAX;

  logger_printf(LOGGER_INFO, "Sending backup freeze to \"%s\"", name);

  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
}

static void tcp_io_read_thread(void * data_void)
{
  struct tcp_conn_info * data = (struct tcp_conn_info *)data_void;

  unsigned char * local_buffer = int_malloc(BUFFER_SIZE + STR_OFFS);
  size_t local_buffer_fill = 0;

  logger_printf(LOGGER_DEBUG, "Auth method: %d", data->auth);
  if (data->auth >= 0) {
    if (tcp_io_read_auth_send(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);

      logger_printf(LOGGER_DEBUG, "Auth error 1");

      exec_with_env(config->onClientConnectFail, 3, buffer);
      goto tcp_read_end;
    }
    if (tcp_io_read_auth_recv(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);

      logger_printf(LOGGER_DEBUG, "Auth error 2");

      exec_with_env(config->onClientConnectFail, 3, buffer);
      goto tcp_read_end;
    }
  } else {
    if (tcp_io_read_auth_recv(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);
      exec_with_env(config->onClientConnectFail, 3, buffer);

      goto tcp_read_end;
    }
    if (tcp_io_read_auth_send(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);
      exec_with_env(config->onClientConnectFail, 3, buffer);

      goto tcp_read_end;
    }
  }

  if (data->cipher != CIPHER_TYPE_NULL) {
    if (tcp_io_read_key_send(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);

      exec_with_env(config->onClientConnectFail, 3, buffer);
      goto tcp_read_end;
    }
    if (tcp_io_read_key_recv(data)) {
      char buffer[256];
      snprintf(buffer, sizeof(buffer) - 1,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
          data->port, 0, config->name, 0, data->name, 0);

      exec_with_env(config->onClientConnectFail, 3, buffer);
      goto tcp_read_end;
    }
  }
  tcp_new_conn(data, 1);

  logger_printf(LOGGER_INFO, "Auth OK: \"%s\"", data->name);

  if (data->incomming == 0) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer) - 1,
        "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
        data->port, 0, config->name, 0, data->name, 0);

    exec_with_env(config->onConnect, 3, buffer);
  } else {
    char buffer[256];
    snprintf(buffer, sizeof(buffer) - 1,
        "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
        data->port, 0, config->name, 0, data->name, 0);
    exec_with_env(config->onClientConnect, 3, buffer);
  }

  uint64_t pass_auth_timeout = 0, max_password_wait_time = 0;

  i_rwlock_rdlock(&conns_sem);
  if (data->flags == CONN_STATUS_FLAG_WAIT_SEND_PASS) {
    struct tcp_pass_data * pass_data = int_malloc(sizeof(*pass_data));

    snprintf(pass_data->env_buffer, sizeof(pass_data->env_buffer) - 1,
        "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
    data->port, 0, config->name, 0, data->name, 0);
    pass_data->conn_id = data->conn_id;
    pass_data->env_count = 3;
    pass_data->cmd = NULL;
    for (size_t i = 0; i < config->static_servers_count; i++) {
      if (config->static_servers[i].conn_id == pass_data->conn_id) {
        pass_data->cmd = strdup(config->static_servers[i].password_injecter);
      }
    }
    pass_data->connection_number = data->conn_id;

    data->pass_thread = thread_new(tcp_read_password, pass_data);
  } else if (data->flags == CONN_STATUS_FLAG_WAIT_RECV_PASS) {
    pass_auth_timeout = getnow_monotonic() / 1000000000LLU;
    max_password_wait_time = config->max_password_wait_time +
    MAX_PASSWORD_RECV_EXTRA_TIME_SEC;
  }
  i_rwlock_rdunlock(&conns_sem);

  int try_again = 0;

  kit_aes_key aes_key;
  kit_twofish_key tf_key;

  if (data->cipher == CIPHER_TYPE_TWOFISH_CTR) {
    uint64_t key[2] = { BSWAP64(data->dec_key[2]), BSWAP64(data->dec_key[3])};
    
    kit_twofish_init_128(&tf_key, (unsigned char *)key);
  } else if (data->cipher == CIPHER_TYPE_AES_CTR) {
    uint64_t key[2] = { BSWAP64(data->dec_key[2]), BSWAP64(data->dec_key[3])};

    kit_aes_init_128(&aes_key, (unsigned char *)key);
  }

  if (data->send_extra_info)
    tcp_sent_extra_info(data);

  size_t buffer_start_ofs = 0;
  size_t checksum_size = get_checksum_size(data->checksum);

  struct pollfd rfd = { data->tcp_conn.sock, POLLIN, 0 };

  while ((!end_now) && (!data->end_now)) {
    if (pass_auth_timeout) {
      if (data->flags != CONN_STATUS_FLAG_WAIT_RECV_PASS) {
        pass_auth_timeout = 0;
        if (data->pass_thread) {
          thread_join(data->pass_thread);
          data->pass_thread = NULL;
        }
      } else if (pass_auth_timeout + max_password_wait_time <
            getnow_monotonic() / 1000000000LLU) {
        logger_printf(LOGGER_ERROR, "password auth timeout with \"%s\"",
            data->name);
        break;
      }
    }

    tcp_ping(data, 0, 0);

    tcp_conn_data_size_t length = BUFFER_SIZE - local_buffer_fill;

    if (!try_again) {
      poll(&rfd, 1, 1000);

      int r = (rfd.revents & POLLIN) ? 1 : 0;

      if (r != 1)
        continue;

      if (buffer_start_ofs > BUFFER_SIZE / 2) {
        memcpy(local_buffer + STR_OFFS,
            local_buffer + buffer_start_ofs + STR_OFFS,
            local_buffer_fill);
        buffer_start_ofs = 0;
      }

      length -= buffer_start_ofs;
      if (length > 0) {
#ifdef PERF_COUNTERS
        uint64_t time1 = 0, time2;
        if (perf_counters.interval > 0)
          time1 = getnow_monotonic();
#endif
        tcp_conn_stat_t stat = tcp_conn_read(&data->tcp_conn,
            local_buffer + local_buffer_fill + buffer_start_ofs + STR_OFFS,
            &length);
#ifdef PERF_COUNTERS
        if (perf_counters.interval > 0) {
          time2 = getnow_monotonic();
          atomic_fetch_add(&perf_counters.tcp_read, time2 - time1);
          atomic_fetch_add(&perf_counters.tcp_read_ctr, 1);
        }
 #endif
        if (stat == TCP_CONN_STAT_ERROR_END_OF_STREAM) {
          logger_printf(LOGGER_ERROR, "TCP error - EOF with \"%s\"",
              data->name);
          break;
        }
        if (stat != TCP_CONN_STAT_OK) {
          logger_printf(LOGGER_ERROR, "TCP error with \"%s\"", data->name);
          break;
        }

        local_buffer_fill += length;
      }
    }
    try_again = 0;

    if (local_buffer_fill < 16)
      continue;

    uint64_t key[4] = {be64toh(data->dec_key[0]), be64toh(data->dec_key[1]),
        BSWAP64(data->dec_key[2]), BSWAP64(data->dec_key[3])};
    key[1] += data->read_blocks;
    if (key[1] < data->read_blocks)
      key[0]++;

    key[0] = htobe64(key[0]);
    key[1] = htobe64(key[1]);

    uint64_t tmp64[2];
    uint8_t * tmp = (uint8_t *)tmp64;
    uint32_t size = 0;

    if (data->cipher == CIPHER_TYPE_TWOFISH_MIXED) {
      kit_twofish_init_128(&tf_key, (unsigned char *)key);
      kit_twofish_decrypt_block(&tf_key, (unsigned char *)tmp,
          &local_buffer[buffer_start_ofs + STR_OFFS]);
    } else if (data->cipher == CIPHER_TYPE_TWOFISH_CTR) {
      uint64_t tmp2[2], lbuf[2];
      memcpy(lbuf, &local_buffer[buffer_start_ofs + STR_OFFS], 16);

      kit_twofish_encrypt_block(&tf_key, (unsigned char *)tmp2,
          (unsigned char *)key);
      tmp64[0] = tmp2[0] ^ lbuf[0];
      tmp64[1] = tmp2[1] ^ lbuf[1];
    } else if (data->cipher == CIPHER_TYPE_AES_MIXED) {
      kit_aes_init_128(&aes_key, (unsigned char *)key);
      kit_aes_decrypt_block(&aes_key, (unsigned char *)tmp,
          &local_buffer[buffer_start_ofs + STR_OFFS]);
    } else if (data->cipher == CIPHER_TYPE_AES_CTR) {
      uint64_t tmp2[2], lbuf[2];
      memcpy(lbuf, &local_buffer[buffer_start_ofs + STR_OFFS], 16);

      kit_aes_encrypt_block(&aes_key, (unsigned char *)tmp2,
          (unsigned char *)key);
      tmp64[0] = tmp2[0] ^ lbuf[0];
      tmp64[1] = tmp2[1] ^ lbuf[1];
    } else if (data->cipher == CIPHER_TYPE_NULL) {
      memcpy(tmp, &local_buffer[buffer_start_ofs + STR_OFFS], 16);
    }
    size = ((tmp[6] << 8) | tmp[7]);
    uint16_t type = ((tmp[4] << 8) | tmp[5]);

    size_t full_size = size + checksum_size;

    if (size > MAX_MTU + CHECKSUM_SIZE_MAX) {
      logger_printf(LOGGER_ERROR, "Encrypted data error with \"%s\" (%hu %hu)",
          data->name, size, full_size);
      break;
    }

    uint32_t pkg_length = BLOCK_SIZE(size + CHECKSUM_SIZE_MAX);
    uint32_t blocks = BLOCK_SIZE(full_size);

    if (blocks > BUFFER_SIZE - local_buffer_fill - buffer_start_ofs) {
      if (buffer_start_ofs > local_buffer_fill) {
        memcpy(local_buffer + STR_OFFS,
            local_buffer + buffer_start_ofs + STR_OFFS,
            local_buffer_fill);
      } else {
        memmove(local_buffer + STR_OFFS,
            local_buffer + buffer_start_ofs + STR_OFFS,
            local_buffer_fill);
      }
      buffer_start_ofs = 0;
    }
    if (blocks > local_buffer_fill)
      continue;

    data->read_blocks += blocks >> 4;
    uint64_t * hmac_key = (uint64_t *)data->hmac_in_key;
        *hmac_key = htobe64(be64toh(*hmac_key) + 1);
    if ((type == PKT_TYPE_ETHERNET_ETHFRAME) ||
        (type == PKT_TYPE_ETHERNET_ENC_PASSWORD) ||
        (type == PKT_TYPE_ETHERNET_ENC_SESSID) ||
        (type == PKT_TYPE_ETHERNET_ENC_EXTRA_INFO) ||
        (type == PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE)) {
      if (data->flags == CONN_STATUS_FLAG_INACTIVE) {
        tcp_new_conn(data, 1);
        tcp_sent_backup_freeze(data->conn_id, data->name);
      }
      if ((data->flags == CONN_STATUS_FLAG_CONNECTED) ||
          (((data->flags >= CONN_STATUS_FLAG_WAIT_RECV_PASS) &&
          (data->flags <= CONN_STATUS_FLAG_WAIT_VERIFY_PASS)) &&
          ((type == PKT_TYPE_ETHERNET_ENC_PASSWORD) ||
          (type == PKT_TYPE_ETHERNET_ENC_SESSID) ||
          (type == PKT_TYPE_ETHERNET_ENC_EXTRA_INFO) ||
          (type == PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE)))) {
        struct packet_record * record =
            (struct packet_record *)(&local_buffer[buffer_start_ofs]);

#ifdef PERF_COUNTERS
        uint64_t time1 = 0, time2;
        if (perf_counters.interval > 0)
          time1 = getnow_monotonic();
        record->perf_start = time1;
#else
        record->live_start = getnow_monotonic();
#endif

        record->msg_type = MSG_TYPE_ENC_NET;
        record->source = data->conn_id;
        record->destination = -1;
        record->net.checksum.type = data->checksum;
        memcpy(record->net.checksum.key, data->hmac_in_key,
            MAX_CHECKSUM_KEY_BYTES);
        memcpy(&record->net.key.key, key, sizeof(key));
        record->net.key.type = data->cipher;
        record->net.bcast_idx = 1;
        record->net.packet_size = size;

        if (data->vlan_id != 0) {
          record->net.vlan_id = data->vlan_id;
          record->net.vlan_opt = VLAN_OPT_ADD_INPUT;
        } else {
          record->net.vlan_id = 0;
          record->net.vlan_opt = VLAN_OPT_DO_NOTHING;
        }

        size_t data_length = STR_OFFS + pkg_length;

        if (data->flags == CONN_STATUS_FLAG_INACTIVE_BACKUP)
          tcp_new_conn(data, 1);

        if ((type != PKT_TYPE_ETHERNET_ETHFRAME) || (!is_mcast(&tmp[8]))) {
          while ((queue_enqueue(global_queue, record, data_length,
              NEEDS_FREE_ENQUEUE, MAX_ENQUEUE_TIME_NS) ==
              QUEUE_STAT_TIMEOUT_WARNING) && (!data->end_now));
        } else {
          i_rwlock_rdlock(&conns_sem);

          if (tap_conn.dev_sock[0] > 0) {
            record->destination = TAP_CONN_ID;
            while ((queue_enqueue(global_queue, record, data_length,
                NEEDS_FREE_ENQUEUE, MAX_ENQUEUE_TIME_NS) ==
                QUEUE_STAT_TIMEOUT_WARNING) && (!data->end_now)) {
              i_rwlock_rdunlock(&conns_sem);
              i_rwlock_rdlock(&conns_sem);
            }
          }

          for (unsigned int i = 0;
                (i < MAX_CONNECTIONS - 1) && (!end_now) && (!data->end_now);
                i++) {
            if (tcp_conn[i].conn_id != data->conn_id) {
              if (tcp_conn[i].flags == CONN_STATUS_FLAG_CONNECTED) {
                record->destination = tcp_conn[i].conn_id;
                record->net.bcast_idx = i + 2;
                while ((queue_enqueue(global_queue, record, data_length,
                    NEEDS_FREE_ENQUEUE, MAX_ENQUEUE_TIME_NS) ==
                    QUEUE_STAT_TIMEOUT_WARNING) && (!data->end_now)) {
                  i_rwlock_rdunlock(&conns_sem);
                  i_rwlock_rdlock(&conns_sem);
                }
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
    } else if (type == PKT_TYPE_ETHERNET_PING) {
      tcp_ping(data, 1, 1);
    }

    data->last_read = getnow_monotonic() / 1000000000LLU;

    buffer_start_ofs += blocks;
    local_buffer_fill -= blocks;

    if (local_buffer_fill >= 16)
      try_again = 1;
  }

  tcp_read_end:;

  send_tcp_close(data);
  int_free(local_buffer);

  logger_printf(LOGGER_INFO, "Closing connection with \"%s\"", data->name);
}

static void tcp_io_write_thread(void * data_void)
{
  struct tcp_conn_info * data = (struct tcp_conn_info *)data_void;

  unsigned int local_buffer_fill = 0;
  unsigned char * local_buffer;

  while ((!end_now) && (!data->end_now)) {
    if (sem_wait_int(&data->write_sem, &data->end_now))
      break;

    while ((!end_now) && (!data->end_now)) {
      unsigned int zero = 0;
      while (!atomic_compare_exchange_strong(&data->buffer_sem, &zero, 1))
        zero = 0;

#ifdef PERF_COUNTERS
      uint64_t time1 = 0, time2;
      if (perf_counters.interval > 0) {
        time1 = getnow_monotonic();
      }
#endif

      local_buffer_fill = data->buffer_fill;
      if (!local_buffer_fill) {
        atomic_store(&data->buffer_sem, 0);
        break;
      }
      data->buffer_fill = 0;
      if (data->buffer == data->buffer_1) {
        local_buffer = data->buffer_1;
        data->buffer = data->buffer_2;
      } else {
        local_buffer = data->buffer_2;
        data->buffer = data->buffer_1;
      }
      atomic_store(&data->buffer_sem, 0);

      size_t offs = 0;

      struct pollfd wfd = { data->tcp_conn.sock, POLLOUT, 0 };
      while ((offs < local_buffer_fill) && (!end_now) && (!data->end_now)) {
        tcp_conn_data_size_t length = local_buffer_fill - offs;
        if (data->mss > 0) {
          if (length > WRITE_PART(data->mss)) {
            length = WRITE_PART(data->mss);
          }
        }

        poll(&wfd, 1, 100);
        if ((wfd.revents & POLLOUT) == 0)
          continue;

        {
#ifdef PERF_COUNTERS
          uint64_t time1 = 0, time2;
          if (perf_counters.interval > 0)
            time1 = getnow_monotonic();
#endif
          if (tcp_conn_write(&data->tcp_conn, local_buffer + offs, &length) !=
              TCP_CONN_STAT_OK)
          {
            logger_printf(LOGGER_ERROR, "TCP write error (%u) %s", errno,
                strerror(errno));
            send_tcp_close(data);
            break;
          }
#ifdef PERF_COUNTERS
          if (perf_counters.interval > 0) {
            time2 = getnow_monotonic();
            atomic_fetch_add(&perf_counters.tcp_write, time2 - time1);
            atomic_fetch_add(&perf_counters.tcp_write_ctr, 1);
          }
#endif
        }
        offs += length;
      }

#ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.tcp_send, time2 - time1);
        atomic_fetch_add(&perf_counters.tcp_send_ctr, 1);
      }
#endif
    }
  }

  atomic_store(&data->buffer_sem, 0);

  char buffer[256];
  snprintf(buffer, sizeof(buffer) - 1,
  "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", data->ipstr,
  data->port, 0, config->name, 0, data->name, 0);

  if (config->onConnectionEnd)
    exec_with_env(config->onConnectionEnd, 3, buffer);
}

void tcp_init(struct tcp_conn_info * info, tcp_conn_t conn, conn_id_t conn_id,
    const struct static_servers_config_t * config, const char * ipstr,
    unsigned short port, unsigned int flags)
{
  static uint32_t connection_number = 0;
  memset(info, 0, sizeof(*info));

  memcpy(&info->tcp_conn, conn, sizeof(*conn));

  if (config)
    info->auth = config->output_auth_method;
  else
    info->auth = -1;

  info->buffer = info->buffer_1;
  info->buffer_fill = 0;
  info->end_now = 0;
  info->written_blocks = 0;
  info->read_blocks = 0;
  info->freeze = TCP_FREEZE_STATUS_UNFREEZE;
  info->flags = flags;

  if (config) {
    if (config->limit_output_buffer_size > 0) {
      if (config->limit_output_buffer_size < MIN_BUFFER_SIZE)
        info->limit_output_buffer_size = MIN_BUFFER_SIZE;
      else if (config->limit_output_buffer_size > MAX_BUFFER_SIZE)
        info->limit_output_buffer_size = MAX_BUFFER_SIZE;
      else
        info->limit_output_buffer_size = config->limit_output_buffer_size;
    } else {
      info->limit_output_buffer_size = MAX_BUFFER_SIZE;
    }
    if ((config->output_auth_method >= OUTPUT_AUTH_METHOD_4) &&
        (config->output_auth_method <= OUTPUT_AUTH_METHOD_5))
      info->output_auth_method = config->output_auth_method;
    else
      info->output_auth_method = OUTPUT_AUTH_METHOD_4;
    info->vlan_id = config->vlan_id;
    memcpy(info->vlan_mask, config->allowed_vlans, sizeof(info->vlan_mask));
  } else {
    info->limit_output_buffer_size = MAX_BUFFER_SIZE;
    info->output_auth_method = -1;
  }

  atomic_store(&info->buffer_sem, 0);
  sem_init(&info->write_sem, 0, 0);

  info->enc_key[0] = 0x0llu;
  info->enc_key[1] = 0x0llu;
  info->enc_key[2] = 0x0llu;
  info->enc_key[3] = 0x0llu;
  info->dec_key[0] = 0x0llu;
  info->dec_key[1] = 0x0llu;
  info->dec_key[2] = 0x0llu;
  info->dec_key[3] = 0x0llu;

  info->conn_id = 0;
  while (!info->conn_id)
    info->conn_id = (((++connection_number) & 0x7FFF) << 16);
  info->conn_id += (conn_id & 0xFFFF);

  if (config) {
    info->timeout[0] = config->keepalive[0];
    info->timeout[1] = config->keepalive[1];
    if (config->limit_output_chunk_size == 0) {
      info->mss = tcp_conn_get_mss(conn);
      if (!info->mss)
        info->mss = DEFAULT_MSS;
    } else {
      info->mss = config->limit_output_chunk_size;
    }
    strncpy(info->name, config->name, sizeof(info->name) - 1);
    strncpy(info->ipstr, ipstr, sizeof(info->ipstr) - 1);
    info->port = port;
    info->cipher = cipher_mode_str_to_int(config->cipher);
    info->checksum = checksum_str_to_int(config->checksum);
    info->incomming = 0;
    info->send_extra_info = config->send_extra_info;
  } else {
    info->timeout[0] = default_keepalive[0];
    info->timeout[1] = default_keepalive[1];
    info->mss = -1;
    memset(info->name, 0, sizeof(info->name));
    strncpy(info->ipstr, ipstr, sizeof(info->ipstr) - 1);
    info->port = port;
    info->cipher = -1;
    info->checksum = -1;
    info->incomming = 1;
    info->send_extra_info = -1;
  }

  atomic_store(&info->close_thread, 0);
  info->start_time = getnow_monotonic();
  info->last_read = getnow_monotonic() / 1000000000LLU;
  info->drops_counter = 0;
  info->io_read_thread = thread_new(tcp_io_read_thread, info);
  info->io_write_thread = thread_new(tcp_io_write_thread, info);
}

void tcp_done(struct tcp_conn_info * info)
{
  info->end_now = 1;

  atomic_store(&info->buffer_sem, 0);
  sem_post(&info->write_sem);

  tcp_conn_close(&info->tcp_conn);

  i_rwlock_switch_wr_rd(&conns_sem);

  thread_join(info->io_read_thread);
  thread_join(info->io_write_thread);
  if (info->pass_thread)
    thread_join(info->pass_thread);

  i_rwlock_switch_rd_wr(&conns_sem);

  intptr_t close_thread;
  if ((close_thread = atomic_load(&info->close_thread))) {
    while ((close_thread = atomic_load(&info->close_thread)) == 1U);
    if (close_thread && (close_thread != 2U))
      thread_join((void *)close_thread);
  }

  sem_destroy(&info->write_sem);

  memset(info, 0, sizeof(*info));
}

static int send_freeze(struct tcp_conn_info * info)
{
  struct packet_record record;
  record.msg_type = MSG_TYPE_FREEZE_CONN;
  record.source = info->conn_id;
  record.destination = info->conn_id;
#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#else
  record.live_start = getnow_monotonic();
#endif
  size_t data_size = ((char *)&record.net - (char *)&record);

  return queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_OK;
}

void tcp_worker(struct tcp_conn_info * info, void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  
#ifdef PERF_COUNTERS
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();
  }
#endif

  if (data->msg_type == MSG_TYPE_DROP) {
    if ((info->freeze == TCP_FREEZE_STATUS_FRREZE) && (!info->buffer_fill)) {
      if (tcp_new_conn(info, 0))
        info->freeze++;
    }

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
      atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type == MSG_TYPE_CHECKSUM_DROP) {
    info->drops_counter++;
    if (info->drops_counter > MAX_DROP_LIMIT) {
      logger_printf(LOGGER_ERROR, "Drops limit exceeded \"%s\"", info->name);
      send_tcp_close(info);
    }

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
      atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type == MSG_TYPE_CLOSE_CONN) {
    sem_post(&info->write_sem);
    info->end_now = 1;
    if (info->flags == CONN_STATUS_FLAG_REMOVED)
      info->flags = CONN_STATUS_FLAG_REMOVED_CLEAN;
    else
      info->flags = CONN_STATUS_FLAG_WAIT_FOR_CLOSE;
    logger_printf(LOGGER_INFO, "Closing TCP connection with \"%s\"",
        info->name);
    intptr_t close_thread;
    if ((close_thread = atomic_load(&info->close_thread))) {
      while ((close_thread = atomic_load(&info->close_thread)) == 1U);
      if (close_thread && (close_thread != 2U)) {
        thread_join((void *)close_thread);
        atomic_compare_exchange_strong(&info->close_thread, &close_thread, 2U);
      }
    }
    return;
  }

  if (data->msg_type == MSG_TYPE_CONN_ACTIVATE) {
    info->flags = CONN_STATUS_FLAG_CONNECTED;
    return;
  }

  if (data->msg_type == MSG_TYPE_CONN_DEACTIVATE) {
    for (size_t j = 0; j < config->static_servers_count; j++) {
      if (config->static_servers[j].conn_id == info->conn_id) {
        if (conn_mode_str_to_int(config->static_servers[j].mode) ==
            CONN_MODE_OFFLINE_BACKUP) {
          send_tcp_close(info);
        }
      }
    }

    info->flags = CONN_STATUS_FLAG_INACTIVE;
    return;
  }

  if (info->freeze) {
    if ((data->msg_type != MSG_TYPE_NEW_CONN) ||
        (data->source != info->conn_id)) {
      if ((info->freeze == TCP_FREEZE_STATUS_FRREZE) && (!info->buffer_fill)) {
        if (tcp_new_conn(info, 0))
          info->freeze++;
      } else if (info->freeze == TCP_FREEZE_STATUS_DESYNC) {
        if (send_freeze(info))
          info->freeze = TCP_FREEZE_STATUS_FRREZE;
      }
#ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        time2 = getnow_monotonic();
        atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
        atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);
      }
#endif
      return;
    }
    info->freeze = TCP_FREEZE_STATUS_UNFREEZE;

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
      atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);
    }
#endif
    return;
  }

  if (data->msg_type != MSG_TYPE_ENC_NET) {
    if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_PASSWORD) {
      char buffer[512];
      uint8_t len = data->net.password.pass_length;
      strcpy(buffer, "PASSWORD=");
      memcpy(buffer + 9, data->net.password.pass_str, len);
      buffer[len + 9] = 0;

      snprintf(buffer + len + 10, sizeof(buffer) - len - 11,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", info->ipstr,
          info->port, 0, config->name, 0, info->name, 0);

      for (size_t j = 0; j < config->static_servers_count; j++) {
        if (config->static_servers[j].conn_id == info->conn_id) {
          logger_printf(LOGGER_DEBUG,
              "Verify password in connection with \"%s\"", info->name);
          char * sessid = NULL;
          size_t sessid_len = MAX_SESSID_LEN;

          if (proc_read_with_env(config->static_servers[j].password_verifier, 4,
              buffer, &sessid, &sessid_len, MAX_PASSWORD_VERIFY_TIME_SEC) == 0)
              {
            info->flags = CONN_STATUS_FLAG_CONNECTED;
            if (config->static_servers[j].send_sessid) {
              if (sessid_len > 0) {
                tcp_password(info->conn_id, sessid_len, sessid,
                    PKT_TYPE_ETHERNET_ENC_SESSID);
              }
            }
          } else {
            send_tcp_close(info);
          }
          int_free(sessid);
        }
      }
    } else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_SESSID) {
      char buffer[512];
      uint8_t len = data->net.password.pass_length;
      strcpy(buffer, "SESSID=");
      memcpy(buffer + 7, data->net.password.pass_str, len);
      buffer[len + 7] = 0;

      snprintf(buffer + len + 8, sizeof(buffer) - len - 9,
          "CLIENT_ADDR=[%s]:%hu%cNAME=%s%cCLIENT_NAME=%s%c", info->ipstr,
          info->port, 0, config->name, 0, info->name, 0);

      int mode = CONN_MODE_NORMAL;
      for (size_t j = 0; j < config->static_servers_count; j++) {
        if (config->static_servers[j].conn_id == info->conn_id) {
          logger_printf(LOGGER_DEBUG, "Save session id connection with \"%s\"",
              info->name);
          exec_with_env(config->static_servers[j].sessid_receiver, 4, buffer);
          mode = conn_mode_str_to_int(config->static_servers[j].mode);
          break;
        }
      }
      if (mode == CONN_MODE_ACTIVE_BACKUP) {
        for (size_t i = 0; i < config->static_servers_count; i++)
          if (config->static_servers[i].backup && 
              strcmp(info->name, config->static_servers[i].backup) == 0) {
          if (is_connected(config->static_servers[i].name))
            info->flags = CONN_STATUS_FLAG_INACTIVE;
          else
            info->flags = CONN_STATUS_FLAG_CONNECTED;
          break;
        }
      } else if (mode == CONN_MODE_NORMAL) {
        info->flags = CONN_STATUS_FLAG_CONNECTED;
      } else if (mode == CONN_MODE_OFFLINE_BACKUP) {
        info->flags = CONN_STATUS_FLAG_CONNECTED;
      } else {
        info->flags = CONN_STATUS_FLAG_WAIT_FOR_CLOSE;
      }
    } else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_EXTRA_INFO) {
      if (be16toh(data->net.length) < sizeof(data->net.extra_info)) {
        logger_printf(LOGGER_ERROR, "Received truncated extra info from \"%s\"",
            info->name);
      } else {
        char prefix[32 + MAX_CLIENT_NAME_LENGTH];
        prefix[sizeof(prefix) - 1] = 0;
        snprintf(prefix, sizeof(prefix) - 1, "Received extra info from \"%s\"",
            info->name);

        log_extra_info_strs(prefix, data->net.extra_info.cryptolib_name_str,
            data->net.extra_info.cryptolib_version_str,
            data->net.extra_info.os_name_str,
            data->net.extra_info.compilation_time_str);
      }
    } else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_BACKUP_FREEZE) {
      if (info->flags == CONN_STATUS_FLAG_CONNECTED)
        info->flags = CONN_STATUS_FLAG_INACTIVE_BACKUP;
    }

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
      atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);
    }
#endif
    return;
  }

  if (info->flags == CONN_STATUS_FLAG_INACTIVE_BACKUP)
    info->flags = CONN_STATUS_FLAG_CONNECTED;

  ssize_t length = data->net.packet_size + get_checksum_size(info->checksum);
  length = BLOCK_SIZE(length);

  unsigned int zero = 0;
  while (!atomic_compare_exchange_strong(&info->buffer_sem, &zero, 1))
    zero = 0;

  ssize_t buffer_free = info->limit_output_buffer_size - info->buffer_fill;
  if (buffer_free < length) {
    info->freeze = TCP_FREEZE_STATUS_DESYNC;
    sem_post(&info->write_sem);
    atomic_store(&info->buffer_sem, 0);
    if (send_freeze(info))
      info->freeze = TCP_FREEZE_STATUS_FRREZE;

#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
      atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);

      time1 = data->perf_start;
      atomic_fetch_add(&perf_counters.pkg_process, time2 - time1);
      atomic_fetch_add(&perf_counters.pkg_process_ctr, 1);
    }
#endif
    return;
  }

  char * local_buffer = (char *)info->buffer;
  memcpy(&local_buffer[info->buffer_fill], &data->net.pkt_idx, length);

  info->written_blocks += length >> 4;
  uint64_t * hmac_key = (uint64_t *)info->hmac_out_key;
  *hmac_key = htobe64(be64toh(*hmac_key) + 1);

  info->buffer_fill += length;

  atomic_store(&info->buffer_sem, 0);
  sem_post(&info->write_sem);

#ifdef PERF_COUNTERS
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.tcp_dequeue, time2 - time1);
    atomic_fetch_add(&perf_counters.tcp_dequeue_ctr, 1);

    time1 = data->perf_start;
    atomic_fetch_add(&perf_counters.pkg_process, time2 - time1);
    atomic_fetch_add(&perf_counters.pkg_process_ctr, 1);
  }
#endif
}
