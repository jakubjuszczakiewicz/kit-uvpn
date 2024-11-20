/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "connection.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "conststr.h"
#include "tcp.h"
#include <clock.h>
#include <logger.h>
#include <exec.h>
#include <utils.h>
#include <dns.h>
#include <threads.h>
#include <rwmutex.h>

#include <memlog.h>

#define MAX_CONNECT_ADDR_LENGHT 128

#define CONNID_CONNECTING (-1)
#define CONNID_FAILED     (-2)

struct conn_init_params
{
  char connect_addr[MAX_CONNECT_ADDR_LENGHT];
  uint16_t connect_port;
  char name[MAX_CLIENT_NAME_LENGTH];
  void * thread;
};

rwmutex_t conns_sem;

struct tap_conn_info tap_conn;
struct tcp_conn_info * tcp_conn = NULL;

static void try_connect(struct static_servers_config_t * server);

int is_connected_int(const char * name)
{
  for (unsigned int i = 0; i < MAX_CONNECTIONS - 1; i++) {
    if (tcp_conn[i].conn_id) {
      if (strncmp(tcp_conn[i].name, name, sizeof(tcp_conn[i].name)) == 0) {
        return 1;
      }
    }
  }

  return 0;
}

static void tcp_activate_conn_wrrd(conn_id_t src, conn_id_t dst, int activate)
{
  struct packet_record record;
  record.msg_type = activate ? MSG_TYPE_CONN_ACTIVATE :
      MSG_TYPE_CONN_DEACTIVATE;
  record.source = src;
  record.destination = dst;
#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#endif

  size_t data_size = ((char *)&record.conn - (char *)&record);

  i_rwlock_switch_wr_rd(&conns_sem);
  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
  i_rwlock_switch_rd_wr(&conns_sem);
}

void tcp_activate_conn(conn_id_t src, conn_id_t dst, int activate)
{
  struct packet_record record;
  record.msg_type = activate ? MSG_TYPE_CONN_ACTIVATE :
      MSG_TYPE_CONN_DEACTIVATE;
  record.source = src;
  record.destination = dst;
#ifdef PERF_COUNTERS
  record.perf_start = getnow_monotonic();
#endif

  size_t data_size = ((char *)&record.conn - (char *)&record);

  while (queue_enqueue(global_queue, &record, data_size, 0,
      MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING) {
    i_rwlock_rdunlock(&conns_sem);
    i_rwlock_rdlock(&conns_sem);
  }
}

static int add_tcp_conn_int(struct tcp_conn_desc_t new_conn,
    struct static_servers_config_t * config, const char * ipstr,
    unsigned short port, unsigned int tcp_flags)
{
  for (int i = 0; i < MAX_CONNECTIONS - 1; i++) {
    if ((tcp_conn[i].conn_id == 0) && (tcp_conn[i].flags == 0)) {
      tcp_init(&tcp_conn[i], &new_conn, i + 1, config, ipstr, port, tcp_flags);

      if (config) {
        config->conn_id = tcp_conn[i].conn_id;
        config->last_reconnect_try = getnow_monotonic() / 1000000000LLU;
      }

      return 1;
    }
  }

  logger_printf(LOGGER_ERROR,
      "Connection with [%s]:%hu failed - out of resources", ipstr, port);
  tcp_conn_close(&new_conn);

  return 0;
}

static int connect_to_ip(const char * addr, uint16_t port, const char * name,
    const char * config_addr)
{
  char buffer[256];
  snprintf(buffer, sizeof(buffer) - 1,
      "SERVER_ADDR=[%s]:%hu%cNAME=%s%cSERVER=%s%c", addr, port, 0, name, 0,
      config_addr, 0);

  exec_with_env(config->onTryConnect, 3, buffer);

  logger_printf(LOGGER_DEBUG, "Try to connect to [%s]:%hu", addr, port);

  struct tcp_conn_desc_t next_conn;
  if (tcp_conn_connect(&next_conn, addr, port) == TCP_CONN_STAT_OK) {
    logger_printf(LOGGER_INFO, "Connected to server %s ([%s]:%hu)", name, addr,
        port);

    i_rwlock_wrlock(&conns_sem);

    struct static_servers_config_t * data = tcp_find_server_by_name(name);
    if (!data) {
      logger_printf(LOGGER_ERROR,
          "Server \"%s\" is disappear in configuration", name);
      i_rwlock_wrunlock(&conns_sem);
      return 0;
    }

    if (!add_tcp_conn_int(next_conn, data, addr, port,
        CONN_STATUS_FLAG_CONNECTING)) {
      data->last_reconnect_try = getnow_monotonic() / 1000000000LLU;
      i_rwlock_wrunlock(&conns_sem);
      exec_with_env(config->onConnectFail, 3, buffer);
      tcp_conn_close(&next_conn);
      return 0;
    }

    data->last_reconnect_try = getnow_monotonic() / 1000000000LLU;
    i_rwlock_wrunlock(&conns_sem);
    exec_with_env(config->onConnect, 3, buffer);

    return 1;
  }

  logger_printf(LOGGER_ERROR, "Connect to server %s ([%s]:%hu) failed", name,
        addr, port);

  i_rwlock_rdlock(&conns_sem);

  struct static_servers_config_t * data = tcp_find_server_by_name(name);
  if (!data) {
    logger_printf(LOGGER_ERROR,
        "Server \"%s\" is disappear in configuration", name);
    i_rwlock_rdunlock(&conns_sem);
    return 0;
  }
  data->last_reconnect_try = getnow_monotonic() / 1000000000LLU;

  i_rwlock_rdunlock(&conns_sem);

  tcp_conn_close(&next_conn);
  exec_with_env(config->onConnectFail, 3, buffer);

  return 0;
}

static int iterate_over_dns(const char * address, unsigned short port,
    void * void_data)
{
  const char ** names = void_data;

  return connect_to_ip(address, port, names[0], names[1]);
}

static void prepare_connect(const char * address, uint16_t port,
    const char * name)
{
  char addr[sizeof(struct sockaddr_in6) > sizeof(struct sockaddr_in) ?
      sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)];
  socklen_t addrlen = sizeof(addr);

  if (ipstr_to_sockaddr(address, port, (struct sockaddr *)addr,
      &addrlen) == 0) {
    const char * names[2] = { name, address };
    if (dns_iterate_by_hostname(address, port, iterate_over_dns, names) > 0)
      return;
  } else {
    if (connect_to_ip(address, port, name, address))
      return;
  }

  if (config->onConnectFail) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer) - 1,
        "SERVER_ADDR=[%s]:%hu%cNAME=%s%cSERVER=%s%c", address, port, 0, name, 0,
        address, 0);
    exec_with_env(config->onConnectFail, 3, buffer);
  }

  struct static_servers_config_t * server = tcp_find_server_by_name(name);

  server->conn_id = CONNID_FAILED;

  if ((server->backup) &&
      (server->backup[0])) {
    struct static_servers_config_t * backup = tcp_find_server_by_name(
        server->backup);
    if (!is_connected_int(backup->name)) {
      i_rwlock_wrlock(&conns_sem);
      try_connect(backup);
      i_rwlock_wrunlock(&conns_sem);
    } else if (backup->conn_id > 0) {
      int k = CONN_ID_NUM(backup->conn_id);
      if (tcp_conn[k].flags == CONN_STATUS_FLAG_INACTIVE) {
        i_rwlock_rdlock(&conns_sem);
        tcp_activate_conn(backup->conn_id, backup->conn_id, 1);
        i_rwlock_rdunlock(&conns_sem);
      }
    }
  }
}

static void try_connect_thread(struct conn_init_params * params)
{
  prepare_connect(params->connect_addr, params->connect_port, params->name);
  int_free(params);
}

static void try_connect(struct static_servers_config_t * server)
{
  if (!server->connect_addr) {
    logger_printf(LOGGER_ERROR,
        "Server connection request without address in config");
    return;
  }

  if (server->conn_thread) {
    logger_printf(LOGGER_DEBUG, "Server connect thread still alive!");
    return;
  }

  struct conn_init_params * params = int_malloc(sizeof(*params));
  strncpy(params->connect_addr, server->connect_addr,
      sizeof(params->connect_addr) - 1);
  params->connect_port = server->connect_port;
  strncpy(params->name, server->name, sizeof(params->name) - 1);

  server->conn_id = CONNID_CONNECTING;
  server->conn_thread = thread_new((void (*)(void *))try_connect_thread,
      params);
}

struct static_servers_config_t * tcp_find_server_by_name(
    const char * name)
{
  struct static_servers_config_t * servers = config->static_servers;
  if (!servers) {
    logger_printf(LOGGER_ERROR, "Servers list is empty!");
    return NULL;
  }

  for (size_t i = 0; i < config->static_servers_count; i++)
    if (strcmp(servers[i].name, name) == 0) {
      logger_printf(LOGGER_DEBUG, "Found \"%s\" server", name);
      return &config->static_servers[i];
    }

  logger_printf(LOGGER_DEBUG, "Server \"%s\" not found", name);
  return NULL;
}

struct static_servers_config_t * tcp_find_master_server_by_name(
    const char * name)
{
  struct static_servers_config_t * servers = config->static_servers;
  if (!servers) {
    logger_printf(LOGGER_ERROR, "Servers list is empty!");
    return NULL;
  }

  for (size_t i = 0; i < config->static_servers_count; i++)
    if (servers[i].backup && servers[i].backup[0]) {
      if (strcmp(servers[i].backup, name) == 0) {
        logger_printf(LOGGER_DEBUG, "Found \"%s\" server", name);
        return &config->static_servers[i];
      }
    }

  logger_printf(LOGGER_DEBUG, "Server \"%s\" not found", name);
  return NULL;
}

int add_tcp_conn(struct tcp_conn_desc_t new_conn,
    struct static_servers_config_t * config, const char * ipstr,
    unsigned short port, unsigned int tcp_flags)
{
  i_rwlock_wrlock(&conns_sem);
  int r = add_tcp_conn_int(new_conn, config, ipstr, port, tcp_flags);
  i_rwlock_wrunlock(&conns_sem);

  return r;
}

void rem_tcp_conn(conn_id_t old_conn)
{
  if (old_conn < 1)
    return;

  logger_printf(LOGGER_DEBUG, "Clean up after connection %08X close", old_conn);
  int i = CONN_ID_NUM(old_conn);

  if (tcp_conn[i].conn_id == 0)
    logger_printf(LOGGER_ERROR, "Connection id is zero!", old_conn);

  tcp_done(&tcp_conn[i]);

  for (size_t j = 0; j < config->static_servers_count; j++) {
    if (config->static_servers[j].conn_id == old_conn) {
      config->static_servers[j].conn_id = 0;
      if (config->static_servers[j].conn_thread) {
        thread_join(config->static_servers[j].conn_thread);
        config->static_servers[j].conn_thread = NULL;
      }

      if ((config->static_servers[j].backup) &&
          (config->static_servers[j].backup[0])) {
        struct static_servers_config_t * backup = tcp_find_server_by_name(
            config->static_servers[j].backup);
        if (!is_connected_int(backup->name)) {
          try_connect(backup);
        } else if (backup->conn_id > 0) {
          int k = CONN_ID_NUM(backup->conn_id);
          if (tcp_conn[k].flags == CONN_STATUS_FLAG_INACTIVE) {
            tcp_activate_conn_wrrd(backup->conn_id, backup->conn_id, 1);
          }
        }
      }
      break;
    }
  }

  tcp_conn[i].name[0] = 0;
  tcp_conn[i].conn_id = 0;
}

int is_connected(const char * name)
{
  i_rwlock_rdlock(&conns_sem);
  
  int r = is_connected_int(name);

  i_rwlock_rdunlock(&conns_sem);
  
  if (r) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" connected - yes", name);
  } else {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" connected - no", name);
  }
  return r;
}

static int is_wait_for_connect(struct static_servers_config_t * server)
{
  if (!server)
    return 0;

  if (strcmp(server->name, config->name) == 0)
    return 0;

  uint64_t now = getnow_monotonic() / 1000000000LLU;

  logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect",
      server->name);

  if (is_connected_int(server->name)) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect - "
        "server already connected",
        server->name);
    return 0;
  }

  if (server->conn_thread) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect - "
        "Server connect thread still alive!", server->name);
    return 0;
  }

  if (server->conn_id) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect - "
        "server already connected", server->name);
    return 0;
  }

  if (!server->auto_connect) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect - "
        "server have turned off autoconnection",
        server->name);
    return 0;
  }

  if (now < (server->last_reconnect_try + server->try_reconnect_sec)) {
    logger_printf(LOGGER_DEBUG, "Check is \"%s\" wait for new connect - "
        "too small delay beetween last try",
        server->name);
    return 0;
  }

  int mode = conn_mode_str_to_int(server->mode);
  if ((mode == CONN_MODE_NORMAL) || (mode == CONN_MODE_ACTIVE_BACKUP)) {
    return 1;
  }

  if (mode == CONN_MODE_REMOVED) {
    logger_printf(LOGGER_DEBUG, "Server \"%s\" don't exists (removed)",
        server->name);
    return 0;
  }

  struct static_servers_config_t * master =
      tcp_find_master_server_by_name(server->name);

  if (!master) {
    logger_printf(LOGGER_DEBUG, "Backup server \"%s\" don't exists",
        server->name);
    return 0;
  }

  if (is_connected_int(master->name))
    return 0;

  return 1;
}

void conns_manager_thread(void * arg)
{
  while (!end_now) {
    i_rwlock_rdlock(&conns_sem);

    for (size_t i = 0; i < config->static_servers_count; i++) {
      if ((config->static_servers[i].conn_id) &&
          (CONN_ID_NUM(config->static_servers[i].conn_id) < MAX_CONNECTIONS)) {
        struct tcp_conn_info * conn =
          &tcp_conn[CONN_ID_NUM(config->static_servers[i].conn_id)];

        if (conn->flags == CONN_STATUS_FLAG_WAIT_FOR_CLOSE) {
          i_rwlock_switch_rd_wr(&conns_sem);
          rem_tcp_conn(config->static_servers[i].conn_id);
          i_rwlock_switch_wr_rd(&conns_sem);
        } else if ((conn->flags == CONN_STATUS_FLAG_CONNECTED) ||
            (conn->flags == CONN_STATUS_FLAG_INACTIVE)) {
          tcp_ping(conn, 0, 0);
        } else if ((conn->flags >= CONN_STATUS_FLAG_ACCEPTING) &&
            (config->static_servers[i].conn_thread)) {
          thread_join(config->static_servers[i].conn_thread);
          i_rwlock_switch_rd_wr(&conns_sem);
          config->static_servers[i].conn_thread = NULL;
          if (conn->flags == CONN_STATUS_FLAG_CAN_T_CONNECT)
            conn->flags = CONN_STATUS_FLAG_FREE;
          i_rwlock_switch_wr_rd(&conns_sem);
        }
      } else if (is_wait_for_connect(&config->static_servers[i])) {
        i_rwlock_switch_rd_wr(&conns_sem);
        try_connect(&config->static_servers[i]);
        i_rwlock_switch_wr_rd(&conns_sem);
      } else if ((config->static_servers[i].conn_thread) &&
            (config->static_servers[i].conn_id) &&
            (config->static_servers[i].conn_id != CONNID_CONNECTING)) {
        thread_join(config->static_servers[i].conn_thread);
        i_rwlock_switch_rd_wr(&conns_sem);
        config->static_servers[i].conn_thread = NULL;
        config->static_servers[i].conn_id = 0;
        i_rwlock_switch_wr_rd(&conns_sem);
      }
    }

    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
      if (tcp_conn[i].flags == CONN_STATUS_FLAG_WAIT_FOR_CLOSE) {
        i_rwlock_switch_rd_wr(&conns_sem);
        rem_tcp_conn(tcp_conn[i].conn_id);
        i_rwlock_switch_wr_rd(&conns_sem);
      } else if (tcp_conn[i].flags == CONN_STATUS_FLAG_REMOVED_CLEAN) {
        i_rwlock_switch_rd_wr(&conns_sem);
        rem_tcp_conn(tcp_conn[i].conn_id);
        for (size_t j = 0; j < config->static_servers_count; j++) {
          if (strcmp(tcp_conn[i].name, config->static_servers[j].name) == 0) {
            config->static_servers_count--;
            memmove(&config->static_servers[j], &config->static_servers[j + 1],
                (config->static_servers_count - j) *
                sizeof(*config->static_servers));
            break;
          }
        }
        i_rwlock_switch_wr_rd(&conns_sem);
      }
    }

    i_rwlock_rdunlock(&conns_sem);
    sleep(1);
  }
}
