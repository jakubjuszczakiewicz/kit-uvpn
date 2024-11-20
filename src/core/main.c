/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>

#include <kitcryptoc/version.h>

#include "global.h"
#include "decrypt.h"
#include "checksum.h"
#include "l2_sw.h"
#include "counter.h"
#include "checksum2.h"
#include "encrypt.h"
#include "tcp.h"
#include "tap.h"
#include "threads.h"
#include "config.h"
#include "version.h"
#include "utils.h"
#include "conststr.h"
#include "perf.h"
#include "workers.h"
#include "connection.h"

#include <queue.h>
#include <tap_int.h>
#include <tcpc.h>
#include <thpool.h>
#include <logger.h>
#include <random.h>
#include <dns.h>
#include <exec.h>
#include <clock.h>
#include <memlog.h>

#define DEFAULT_PORT 1193
#define DEFAULT_MAX_ARP_TTL 120
#define DEFAULT_MAX_PASSWORD_WAIT_TIME (60 * 2)
#define CONN_STAT_STR_DUMP_ALLOC_STEP 10240
#define STRTIME_SIZE 32

const unsigned short default_keepalive[2] = { 30, 45 };

volatile int end_now = 0;

queue_t global_queue;

struct RSA * thiz_rsa;

struct thpool_t * decrypt_thpool;
struct thpool_t * encrypt_thpool;
struct thpool_t * checksum_thpool;
struct thpool_t * checksum2_thpool;

#ifdef PERF_COUNTERS
struct perf_counters perf_counters;
#endif

void * connection_thread = NULL;

queue_worker_t queue_consumers_long[7] = {
  decrypt_consumer, checksum_consumer, l2_sw_consumer, counter_consumer,
  checksum2_consumer, encrypt_consumer, conn_consumer
};

queue_worker_t queue_consumers_short[5] = {
  crypto_in_consumer, l2_sw_consumer, counter_consumer, crypto_out_consumer,
  conn_consumer
};

const char si_prefixes[] = { ' ', 'k', 'M', 'G', 'T', 'P' };

char cryptolib_name_str[LIB_NAME_STR_LEN];
char cryptolib_version_str[VERSION_STR_LEN];
char os_name_str[OS_NAME_STR_LEN];
char compilation_time_str[COMPILATIION_TIME_STR_LEN];

void log_extra_info_strs(const char * prefix, const char * cryptolib_name,
    const char * cryptolib_ver, const char * os_name, const char * ct_str)
{
  size_t cryptolib_name_len = strnlen(cryptolib_name, LIB_NAME_STR_LEN);
  size_t cryptolib_ver_len = strnlen(cryptolib_ver, VERSION_STR_LEN);
  size_t os_name_len = strnlen(os_name, OS_NAME_STR_LEN);
  size_t ct_str_len = strnlen(ct_str, COMPILATIION_TIME_STR_LEN);

  logger_printf(LOGGER_INFO,
      "%s %*s version %*s with %*s %*s on %*s. Comment: \"%*s\"",
      prefix, kit_uvpn_name_len, kit_uvpn_name, kit_uvpn_version_str_len,
      kit_uvpn_version_str, cryptolib_name_len, cryptolib_name,
      cryptolib_ver_len, cryptolib_ver, os_name_len, os_name, ct_str_len,
      ct_str);
}

static void init_extra_info_strs(void)
{
  memset(cryptolib_name_str, 0, sizeof(cryptolib_name_str));
  memset(cryptolib_version_str, 0, sizeof(cryptolib_version_str));
  memset(os_name_str, 0, sizeof(os_name_str));
  memset(compilation_time_str, 0, sizeof(compilation_time_str));

  strncpy(cryptolib_name_str, KIT_CRYPT_C_LIB_NAME, sizeof(cryptolib_name_str));
  snprintf(cryptolib_version_str, sizeof(cryptolib_version_str), "%u.%u.%u",
      kit_crypto_c_version[0], kit_crypto_c_version[1],
      kit_crypto_c_version[2]);
  strncpy(os_name_str, OS_STR, sizeof(os_name_str));
  strncpy(compilation_time_str, CT_TIME_STR, sizeof(compilation_time_str));

  log_extra_info_strs("Start", cryptolib_name_str, cryptolib_version_str,
      os_name_str, compilation_time_str);
}

int is_mcast(unsigned char * mac)
{
  return (mac[0] & 1) != 0;
}

static void on_signal_term(int signum)
{
  end_now = 1;
}

static void config_reload()
{
  struct static_servers_config_t * new_config = NULL;
  size_t new_sections = 0;
  int success;

  i_rwlock_wrlock(&conns_sem);

  if (config->servers_config) {
    if (parse_servers_file(config->servers_config, &new_config,
        &new_sections)) {
      logger_printf(LOGGER_ERROR, "Reload ini file failed");
      free_servers_data(new_config, new_sections);
      i_rwlock_wrunlock(&conns_sem);
      return;
    }
  } else {
    logger_printf(LOGGER_ERROR, "Missing path to servers config ini file");
    i_rwlock_wrunlock(&conns_sem);
    return;
  }

  success = 1;

  for (size_t i = 0; i < new_sections; i++) {
    if (cipher_mode_str_to_int(new_config[i].cipher) < 0) {
      logger_printf(LOGGER_ERROR, "Invalid cipher (%s) in %s",
          new_config[i].cipher, new_config[i].name);
      success = 0;
    }
    if (checksum_str_to_int(new_config[i].checksum) < 0) {
      logger_printf(LOGGER_ERROR, "Invalid checksum (%s) in %s",
          new_config[i].checksum, new_config[i].name);
      success = 0;
    }
    if (conn_mode_str_to_int(new_config[i].mode) < 0) {
      logger_printf(LOGGER_ERROR, "Invalid mode (%s) in %s",
          new_config[i].mode, new_config[i].name);
      success = 0;
    }
    if ((new_config[i].backup) && (new_config[i].backup[0])) {
      size_t j;
      for (j = 0; j < new_sections; j++) {
        if ((i != j) && (strcmp(new_config[i].backup, new_config[j].name) == 0))
          break;
      }
      if (j == new_sections) {
        logger_printf(LOGGER_ERROR,
          "No backup section name in servers ini file (%s)",
          new_config[i].backup);
        success = 0;
      } else {
        int mode = conn_mode_str_to_int(new_config[j].mode);
        if ((mode != CONN_MODE_OFFLINE_BACKUP) &&
            (mode != CONN_MODE_ACTIVE_BACKUP)) {
          logger_printf(LOGGER_ERROR,
              "Backup connection isn't backup mode in servers ini file (%s)",
              new_config[j].name);
          success = 0;
        }          
      }
    }
  }
  if (!success) {
    i_rwlock_wrunlock(&conns_sem);
    free_servers_data(new_config, new_sections);
    logger_printf(LOGGER_ERROR, "Reload ini file failed");
    return;
  }

  qsort(new_config, new_sections, sizeof(new_config[0]),
      (int (*)(const void *, const void *))server_config_cmp_name);

  for (size_t i = 0; i + 1 < new_sections; i++) {
    if (strcmp(new_config[i].name, new_config[i + 1].name) == 0) {
      i_rwlock_wrunlock(&conns_sem);
      logger_printf(LOGGER_ERROR,
          "Duplicated section name in servers ini file (%s)",
          new_config[i].name);
      free_servers_data(new_config, new_sections);
      logger_printf(LOGGER_ERROR, "Reload ini file failed");
      return;
    }
  }

  if (!config->static_servers) {
    config->static_servers = new_config;
    config->static_servers_count = new_sections;
    i_rwlock_wrunlock(&conns_sem);
    logger_printf(LOGGER_ERROR, "Reloaded ini file without error");
    return;
  }

  size_t i, j = 0;
  for (i = 0; (i < new_sections) && (j < config->static_servers_count);) {
    int cmp = server_config_cmp_name(&new_config[i],
        &config->static_servers[j]);
    if (cmp == 0) {
      new_config[i].last_reconnect_try =
          config->static_servers[j].last_reconnect_try;
      new_config[i].conn_id = config->static_servers[j].conn_id;
      new_config[i].conn_thread = config->static_servers[j].conn_thread;

      if (server_config_cmp_full(&new_config[i], &config->static_servers[j])) {
        tcp_conn[CONN_ID_NUM(new_config[i].conn_id)].flags =
            CONN_STATUS_FLAG_REMOVED;
      }

      j++;
      i++;
    } else if (cmp > 0) {
      if (config->static_servers[j].conn_id > 0) {
        tcp_conn[CONN_ID_NUM(config->static_servers[j].conn_id)].flags =
            CONN_STATUS_FLAG_REMOVED;
        new_config = int_realloc(new_config,
            (new_sections + 1) * sizeof(*new_config));

        memmove(&new_config[i + 1], &new_config[i],
            (new_sections - i) * sizeof(*new_config));
        memcpy(&new_config[i], &config->static_servers[j], sizeof(*new_config));
        if (new_config[i].mode) {
          int_free(new_config[i].mode);
        }
        new_config[i].mode = int_strdup("removed");

        config->static_servers_count--;
        memmove(&config->static_servers[j], &config->static_servers[j + 1],
                (config->static_servers_count - j) *
                sizeof(*config->static_servers));

        new_sections++;
        i++;
      } else {
        j++;
      }
    } else {
      i++;
    }
  }

  for (;j < config->static_servers_count; j++) {
    if (config->static_servers[j].conn_id > 0) {
      tcp_conn[CONN_ID_NUM(config->static_servers[j].conn_id)].flags =
          CONN_STATUS_FLAG_REMOVED;
    }
  }

  free_servers_data(config->static_servers, config->static_servers_count);
  config->static_servers = new_config;
  config->static_servers_count = new_sections;

  i_rwlock_wrunlock(&conns_sem);
  logger_printf(LOGGER_ERROR, "Reloaded ini file without error");

  i_rwlock_rdlock(&conns_sem);
  for (i = 0; i < config->static_servers_count; i++) {
    if ((config->static_servers[i].conn_id > 0) &&
        (tcp_conn[CONN_ID_NUM(config->static_servers[i].conn_id)].flags ==
        CONN_STATUS_FLAG_REMOVED)) {
      send_tcp_close(&tcp_conn[CONN_ID_NUM(config->static_servers[i].conn_id)]);
    }
  }
  i_rwlock_rdunlock(&conns_sem);
}

static void on_signal_config_reload(int signum)
{
  config_reload();
}

static void on_signal_logs_reload(int signum)
{
  logger_reopen();
}

static void on_signal_clear_arp(int signum)
{
  struct packet_record record;
  memset(&record, 0, sizeof(record));

  record.msg_type = MSG_TYPE_CLEAR_ARP;

  size_t data_size = ((char *)&record.conn - (char *)&record);

  while (queue_enqueue(global_queue, &record, data_size, 0,
    MAX_ENQUEUE_TIME_NS) == QUEUE_STAT_TIMEOUT_WARNING);
}

static void print_cat_bytes(struct str_t * str, uint64_t bytes)
{
  if (bytes < 1024) {
    print_cat(str, "%lluB", bytes);
    return;
  }

  uint64_t base = 1024;
  size_t i;

  for (i = 1; i < sizeof(si_prefixes) / sizeof(si_prefixes[0]); i++) {
    if (base * 1024 > bytes)
      break;
    base *= 1024;
  }

  print_cat(str, "%0.2f%ciB", (double)bytes / (double)base, si_prefixes[i]);
}

static void conn_stat_dump_file(void)
{
  if (!config->conn_stat_dump_file)
    return;

  i_rwlock_rdlock(&conns_sem);

  char timestr[STRTIME_SIZE];
  time_t now = time(NULL);
  struct tm now_tm;
  localtime_r(&now, &now_tm);
  strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", &now_tm);

  struct str_t buffer = { int_malloc(1), 0 };
  buffer.str[0] = 0;

  print_cat(&buffer, "%s\n\n", timestr);

  for (size_t i = 0; i < config->static_servers_count; i++) {
    print_cat(&buffer, "Name: %s", config->static_servers[i].name);
    struct tcp_conn_info * conn_info = NULL;
    if (config->static_servers[i].conn_id > 1) {
      conn_info = &tcp_conn[CONN_ID_NUM(config->static_servers[i].conn_id)];
    }

    if (conn_info) {
      print_cat(&buffer, ": [%s]:%hu\n", conn_info->ipstr, conn_info->port);
      if (conn_info->freeze) {
        print_cat(&buffer, "Status: freezed");
      } else {
        print_cat(&buffer, "Status: unfreezed");
      }
      if (conn_info->incomming) {
        print_cat(&buffer, ", incomming");
      } else {
        print_cat(&buffer, ", outgoing");
      }

      const char * flags = conn_status_flag_to_str(conn_info->flags);
      print_cat(&buffer, ", %s", flags);

      print_cat(&buffer, "\n");
      uint64_t uptime = getnow_monotonic() - conn_info->start_time;
      print_cat(&buffer, "Uptime: %usec, mode: %s\n", uptime / 1000000000LLU,
          config->static_servers[i].mode ?
          config->static_servers[i].mode : "normal");
      uint64_t read = conn_info->read_blocks * 16;
      uint64_t written = conn_info->written_blocks * 16;

      print_cat(&buffer, "TX: %lluB", written);
      if (written >= 1024) {
        print_cat(&buffer, " (");
        print_cat_bytes(&buffer, written);
        print_cat(&buffer, ")");
      }

      print_cat(&buffer, ", RX: %lluB", read);
      if (read >= 1024) {
        print_cat(&buffer, " (");
        print_cat_bytes(&buffer, read);
        print_cat(&buffer, ")");
      }
      print_cat(&buffer, "\nDropped packages: %u\n", conn_info->drops_counter);
    } else {
      print_cat(&buffer, ": diconnected, mode: %s\n",
          config->static_servers[i].mode ?
          config->static_servers[i].mode : "normal");
    }
    print_cat(&buffer, "\n");
  }
  i_rwlock_rdunlock(&conns_sem);

  FILE * f = fopen(config->conn_stat_dump_file, "w");
  if (f) {
    fwrite(buffer.str, buffer.size, 1, f);
    fclose(f);
  } else {
    logger_printf(LOGGER_ERROR, "Unable to open file \"%s\": %s",
        config->conn_stat_dump_file, strerror(errno));
  }
  int_free(buffer.str);
}

int main(int argc, char * argv[])
{
  int r = config_load(argc - 1, argv + 1);
  if (r) {
    fprintf(stderr, "Configuration error!\n");
    return r;
  }

  if (!config->private_key) {
    fprintf(stderr, "Private key path not found!\n");
    return 1;
  }

  int dict_alg = dict_alg_str_to_int(config->dict_alg);
  if (dict_alg < 0) {
    fprintf(stderr, "Invalid dict algorithm\n");
    return 1;
  }

  tcp_conn = int_calloc(sizeof(struct tcp_conn_info), MAX_CONNECTIONS + 1);
  if (!tcp_conn) {
    fprintf(stderr, "Unable to allocate memory!!!\n");
    return 1;
  }

  random_init();

  thiz_rsa = load_rsakey(config->private_key);
  if (!thiz_rsa) {
    fprintf(stderr, "Unable to load private key from file: %s!\n",
        config->private_key);
    return 1;
  }

  int queue_layout = queue_layout_str_to_int(config->queue_layout);
  if (queue_layout == QUEUE_LAYOUT_INVALID) {
    fprintf(stderr, "Invalid queue layout: %s!\n", config->queue_layout);
    return 1;
  }

  if (!config->forground) {
    (void)daemon(1, 0);
  }

  if (config->log_file)
    logger_init(config->log_file, config->log_level);
  else if (config->forground)
    logger_init("/dev/stderr", config->log_level);
  else
    logger_init("/dev/null", 0);

  if (queue_layout == QUEUE_LAYOUT_LONG) {
    if (config->crypto_workers > MAX_CRYPTO_WORKERS)
      config->crypto_workers = MAX_CRYPTO_WORKERS;
    if (config->checksum_workers > MAX_CHECKSUM_WORKERS)
      config->checksum_workers = MAX_CHECKSUM_WORKERS;

    logger_printf(LOGGER_INFO, "Starting %s %s with 2x%u "
        "crypto workers and 2x%u checksum worker(s)", kit_uvpn_name,
        kit_uvpn_version_str, config->crypto_workers,
        config->checksum_workers);
  } else {
    config->crypto_workers += config->checksum_workers;
    if (config->crypto_workers > MAX_CRYPTO_WORKERS)
      config->crypto_workers = MAX_CRYPTO_WORKERS;

    logger_printf(LOGGER_INFO, "Starting %s %s with 2x%u "
        "crypto workers", kit_uvpn_name, kit_uvpn_version_str,
        config->crypto_workers, config->checksum_workers);
  }

  init_extra_info_strs();

  if (config->pid_file) {
    FILE * file = fopen(config->pid_file, "w");
    if (file) {
      fprintf(file, "%u\n", getpid());
      fclose(file);
    }
  }

#ifdef PERF_COUNTERS
  if ((config->perf_counter_dump_interval > 0) &&
      (config->perf_counter_dump_file)) {
    perf_counters.interval = config->perf_counter_dump_interval;
    perf_counters.last_dump = getnow_monotonic() / 1000000000LLU;
  } else {
    perf_counters.interval = 0;
    perf_counters.last_dump = 0;
  }
#endif

  if (queue_layout == QUEUE_LAYOUT_LONG) {
    decrypt_init();
    checksum_init();
    checksum2_init();
    encrypt_init();
  } else {
    crypto_in_init();
    crypto_out_init();
  }

#ifdef PERF_COUNTERS
  perf_init(&perf_counters);
#endif

  i_rwlock_init(&conns_sem);

  if (queue_layout == QUEUE_LAYOUT_LONG) {
    decrypt_thpool = thpool_create(config->crypto_workers,
        decrypt_thread_executor);
    encrypt_thpool = thpool_create(config->crypto_workers,
        encrypt_thread_executor);
    checksum_thpool = thpool_create(config->checksum_workers,
        checksum_thread_executor);
    checksum2_thpool = thpool_create(config->checksum_workers,
        checksum2_thread_executor);
  } else {
    decrypt_thpool = thpool_create(config->crypto_workers,
        crypto_in_thread_executor);
    encrypt_thpool = thpool_create(config->crypto_workers,
        crypto_out_thread_executor);
  }
  counter_init();

  l2_sw_init((config->max_arp_ttl == 0) 
      ? DEFAULT_MAX_ARP_TTL : config->max_arp_ttl, dict_alg);

  if (config->queue_size < 10)
    config->queue_size = 10;

  if (queue_layout == QUEUE_LAYOUT_LONG) {
    queue_init(&global_queue, config->queue_size,
        sizeof(queue_consumers_long) / (sizeof(queue_consumers_long[0])),
        queue_consumers_long);
  } else {
    queue_init(&global_queue, config->queue_size,
        sizeof(queue_consumers_short) / (sizeof(queue_consumers_short[0])),
        queue_consumers_short);
  }

  signal(SIGTERM, &on_signal_term);
  signal(SIGINT, &on_signal_term);
  signal(SIGUSR1, &on_signal_config_reload);
  signal(SIGUSR2, &on_signal_clear_arp);
  signal(SIGHUP, &on_signal_logs_reload);
  signal(SIGPIPE, SIG_IGN);

  int tapint[TAP_QUEUES];
  memset(tapint, 0, sizeof(int) * TAP_QUEUES);
  if (config->tap_name) {
    logger_printf(LOGGER_INFO, "Creating tap interface (%s)", config->tap_name);

    if (tap_create(config->tap_name, tapint, TAP_QUEUES) < 0) {
      logger_printf(LOGGER_ERROR, "Unable to create tap interface (%s): %s",
          config->tap_name, strerror(errno));
      goto end;
    }

    logger_printf(LOGGER_INFO, "Created tap interface (%s): %d",
          config->tap_name, tapint[0]);

    char buffer[64];
    snprintf(buffer, sizeof(buffer) - 1, "TAP=%s%cNAME=%s%c", config->tap_name,
          0, config->name, 0);

    exec_with_env(config->onTapCreate, 2, buffer);
  }

  config_reload();

  i_rwlock_rdlock(&conns_sem);

  logger_printf(LOGGER_INFO, "Loaded configuration for %zu servers",
      config->static_servers_count);

  if (!config->max_password_wait_time) {
    config->max_password_wait_time = DEFAULT_MAX_PASSWORD_WAIT_TIME;
  }

  i_rwlock_rdunlock(&conns_sem);

  if (config->tap_name) {
    tap_init(&tap_conn, tapint, TAP_CONN_ID);
  } else {
    memset(tap_conn.dev_sock, 0, sizeof(int) * TAP_QUEUES);
    tap_conn.bcast_counter = 0;
    tap_conn.io_read_thread = NULL;
    memset(&tap_conn.io_write_thread, 0, sizeof(tap_conn.io_write_thread));
  }

  struct tcp_conn_desc_t conn;

  if (config->listen_addr && config->listen_port) {
    logger_printf(LOGGER_INFO, "Open TCP socket for listen at [%s]:%hu",
        config->listen_addr, config->listen_port);

    tcp_conn_stat_t stat = tcp_conn_listen(&conn, config->listen_addr,
        config->listen_port);
    if (stat != TCP_CONN_STAT_OK) {
      logger_printf(LOGGER_ERROR, "Unable to open TCP socket"
          " for listen at [%s]:%hu (%u)", config->listen_addr,
          config->listen_port, stat);
      goto end;
    }

    if (config->onTcpListen) {
      char buffer[128];
      snprintf(buffer, sizeof(buffer) - 1, "LISTEN=[%s]:%hu%cNAME=%s%c",
          config->listen_addr, config->listen_port, 0, config->name, 0);

      exec_with_env(config->onTcpListen, 2, buffer);
    }
  } else
    conn.sock = 0;

  connection_thread = thread_new(conns_manager_thread, NULL);
  uint64_t conn_stat_last_dump = getnow_monotonic() / 1000000000LLU;

  while (!end_now) {
    int r = 0;

    while (!end_now) {
      uint64_t now = getnow_monotonic() / 1000000000LLU;
#ifdef PERF_COUNTERS
      if (perf_counters.interval > 0) {
        if (perf_counters.last_dump + perf_counters.interval < now) {
          dump_perf_counters(config->perf_counter_dump_file, &perf_counters,
              queue_fill_ratio(global_queue));
          perf_counters.last_dump = now;
        }
      }
#endif
      if (config->conn_stat_dump_interval > 1) {
        if (now > config->conn_stat_dump_interval + conn_stat_last_dump) {
          conn_stat_dump_file();
          conn_stat_last_dump = now;
        }
      }

      if (!conn.sock) {
        sleep(1);
        continue;
      }

      fd_set set;
      FD_ZERO(&set);
      FD_SET(conn.sock, &set);
      struct timeval timeout;
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      r = select(conn.sock + 1, &set, NULL, NULL, &timeout);

      if (r < 0) {
        logger_printf(LOGGER_ERROR, "Select error (%u) %s", errno,
            strerror(errno));
      } else if (r != 0)
        break;
    }

    if ((r == 1) && (!end_now)) {
      char ipstr[64];
      struct tcp_conn_desc_t new_conn;

      unsigned short port = 0;
      if (tcp_conn_accept(&conn, ipstr, &port, &new_conn) == TCP_CONN_STAT_OK) {
        logger_printf(LOGGER_INFO, "Accept new TCP connection"
            " from listen at [%s]:%hu", ipstr, port);
        add_tcp_conn(new_conn, NULL, ipstr, port, CONN_STATUS_FLAG_ACCEPTING);
      }
    }
  }

  tcp_conn_close(&conn);

end:;
  logger_printf(LOGGER_INFO, "Start closing uVPN");
  end_now = 1;

  i_rwlock_rdlock(&conns_sem);
  i_rwlock_switch_rd_wr(&conns_sem);
  for (unsigned int i = 0; i < MAX_CONNECTIONS - 1; i++)
    if (tcp_conn[i].conn_id)
      rem_tcp_conn(tcp_conn[i].conn_id);
  i_rwlock_switch_wr_rd(&conns_sem);
  i_rwlock_rdunlock(&conns_sem);

  if (config->tap_name) {
    tap_done(&tap_conn);
    tap_destroy(tapint, TAP_QUEUES);
  }

  sleep(1);

  queue_close(global_queue);
  counter_done();
  l2_sw_done();

  thpool_dispose(decrypt_thpool);
  thpool_dispose(encrypt_thpool);

  if (queue_layout == QUEUE_LAYOUT_LONG) {
    thpool_dispose(checksum_thpool);
    thpool_dispose(checksum2_thpool);
  }

  if (connection_thread)
    thread_join(connection_thread);

  if (config->pid_file)
    unlink(config->pid_file);

  config_done();
  rsa_done(thiz_rsa);
  logger_close();
  random_done();

  int_free(tcp_conn);

  return 0;
}
