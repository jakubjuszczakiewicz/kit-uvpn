/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "rsa.h"
#include "global.h"

struct static_servers_config_t
{
  char * name;
  char * connect_addr;
  unsigned short connect_port;
  char * public_key;
  unsigned short keepalive[2];
  unsigned char auto_connect;
  unsigned char allow_new_connect;
  unsigned short try_reconnect_sec;
  char * cipher;
  char * checksum;
  unsigned long limit_output_buffer_size;
  unsigned char output_auth_method;
  long limit_output_chunk_size;
  char * mode;
  char * backup;
  char * password_verifier;
  char * password_injecter;
  char * sessid_receiver;
  unsigned char send_sessid;
  unsigned char send_extra_info;

  // non configurable part
  uint64_t last_reconnect_try;
  conn_id_t conn_id;
  void * conn_thread;
};

struct config_t
{
  char * name;
  char * listen_addr;
  unsigned short listen_port;
  unsigned char crypto_workers;
  unsigned char checksum_workers;
  char * tap_name;
  char * private_key;
  char * servers_config;
  char * log_file;
  char * pid_file;
  unsigned short log_level;
  unsigned char forground;
  unsigned short queue_size;
  unsigned long max_arp_ttl;
  char * dict_alg;
  unsigned short max_password_wait_time;
#ifdef PERF_COUNTERS
  char * perf_counter_dump_file;
  unsigned short perf_counter_dump_interval;
#endif
  char * conn_stat_dump_file;
  unsigned short conn_stat_dump_interval;
  char * queue_layout;

  char * onTapCreate;
  char * onTcpListen;
  char * onClientConnect;
  char * onConnect;
  char * onClientConnectFail;
  char * onConnectFail;
  char * onConnectionEnd;
  char * onTryConnect;

  // non configurable part
  size_t static_servers_count;
  struct static_servers_config_t * static_servers;
};

extern struct config_t * config;

int config_load(int argc, char * argv[]);
void config_done();

int parse_servers_file(const char * path,
    struct static_servers_config_t ** config, size_t * sections);
void free_servers_data(struct static_servers_config_t * config,
    size_t sections);

int server_config_cmp_name(const struct static_servers_config_t * a,
    const struct static_servers_config_t * b);

long server_config_cmp_full(const struct static_servers_config_t * a,
    const struct static_servers_config_t * b);

struct RSA * load_rsakey(const char * path);

#endif
