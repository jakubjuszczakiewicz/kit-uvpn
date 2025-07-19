/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <tcpc.h>
#include <semaphore.h>
#include <pthread.h>
#include <queue.h>
#include <rsa.h>
#include <rwmutex.h>
#include "perf.h"

#define MAX_CHECKSUM_KEY_BYTES 128
#define MAX_CIPHER_KEY_SIZE 32

typedef int32_t conn_id_t;
typedef struct
{
  uint64_t key[(MAX_CIPHER_KEY_SIZE / 8)];
  int32_t type;
} encrypt_key_t;

typedef struct
{
  union {
    uint64_t u64;
    uint8_t key[MAX_CHECKSUM_KEY_BYTES];
  };
  int16_t type;
} checksum_t;

extern volatile int end_now;

#define VLAN_PROTO_ID 0x8100

#define CIPHER_TYPE_TWOFISH_MIXED 0
#define CIPHER_TYPE_TWOFISH_CTR   1
#define CIPHER_TYPE_AES_MIXED     2
#define CIPHER_TYPE_AES_CTR       3
#define CIPHER_TYPE_NULL          4
#define CIPHER_TYPE_DEFAULT       CIPHER_TYPE_TWOFISH_MIXED

#define CIPHER_KEY_SIZE_TWOFISH_MIXED 2
#define CIPHER_KEY_SIZE_TWOFISH_CTR   4
#define CIPHER_KEY_SIZE_AES_MIXED     2
#define CIPHER_KEY_SIZE_AES_CTR       4
#define CIPHER_KEY_SIZE_NULL          0

#define CHECKSUM_NONE        0
#define CHECKSUM_SHA224      1
#define CHECKSUM_SHA256      2
#define CHECKSUM_SHA384      3
#define CHECKSUM_SHA512      4
#define CHECKSUM_SHA224_HMAC 5
#define CHECKSUM_SHA256_HMAC 6
#define CHECKSUM_SHA384_HMAC 7
#define CHECKSUM_SHA512_HMAC 8
#define CHECKSUM_DEFAULT  CHECKSUM_SHA256

#define CHECKSUM_SIZE_NONE        0
#define CHECKSUM_SIZE_SHA224      28
#define CHECKSUM_SIZE_SHA256      32
#define CHECKSUM_SIZE_SHA384      48
#define CHECKSUM_SIZE_SHA512      64
#define CHECKSUM_SIZE_SHA224_HMAC 28
#define CHECKSUM_SIZE_SHA256_HMAC 32
#define CHECKSUM_SIZE_SHA384_HMAC 48
#define CHECKSUM_SIZE_SHA512_HMAC 64

#define CHECKSUM_SHA224_HAMC_KEY_SIZE 64
#define CHECKSUM_SHA256_HAMC_KEY_SIZE 64
#define CHECKSUM_SHA384_HAMC_KEY_SIZE 128
#define CHECKSUM_SHA512_HAMC_KEY_SIZE 128

#define CHECKSUM_SIZE_MAX      64

#ifndef MAX_CONNS
#define MAX_CONNECTIONS 512
#else
#define MAX_CONNECTIONS (MAX_CONNS)
#endif

#ifdef AUTH_BUFFER_SIZE
#if AUTH_BUFFER_SIZE < 65537
#warning AUTH_BUFFER_SIZE should be at least 65537
#endif
#endif

#define TAP_CONN_ID 0x010000

#define MIN_BUFFER_SIZE (15360)

#ifndef MAX_BUFFER_SIZE
#define BUFFER_SIZE (153600)
#else
#define BUFFER_SIZE (MAX_BUFFER_SIZE)
#endif

#ifndef AUTH_BUFFER_SIZE
#define AUTH_BUFFER_SIZE (15360)
#endif

#ifndef MAX_DROP_LIMIT
#define MAX_DROP_LIMIT 1
#endif

#define MAX_CLIENT_NAME_LENGTH 64

#define DICT_ALGORITHM_AVL_16     0
#define DICT_ALGORITHM_AVL_24     1
#define DICT_ALGORITHM_HASHTAB_16 2
#define DICT_ALGORITHM_HASHTAB_24 3

#define CONN_MODE_NORMAL         0
#define CONN_MODE_OFFLINE_BACKUP 1
#define CONN_MODE_ACTIVE_BACKUP  2
#define CONN_MODE_REMOVED        3

#define MSG_TYPE_CLOSE_APP       0
#define MSG_TYPE_RAW_NET         1
#define MSG_TYPE_ENC_NET         2
#define MSG_TYPE_DROP            3
#define MSG_TYPE_CHECKSUM_DROP   4
#define MSG_TYPE_NEW_CONN        5
#define MSG_TYPE_CLOSE_CONN      6
#define MSG_TYPE_FREEZE_CONN     7
#define MSG_TYPE_CLEAR_ARP       8
#define MSG_TYPE_CONN_ACTIVATE   9
#define MSG_TYPE_CONN_DEACTIVATE 10
#define MSG_TYPE_INVALID         11

#define OUTPUT_AUTH_METHOD_4       4
#define OUTPUT_AUTH_METHOD_5       5

#ifndef MAX_MTU
#define MAX_MTU 1540
#endif

#ifndef MAX_CRYPTO_WORKERS
#define MAX_CRYPTO_WORKERS 32
#endif

#ifndef MAX_CHECKSUM_WORKERS
#define MAX_CHECKSUM_WORKERS 32
#endif

#define LOGGER_ERROR   0 
#define LOGGER_INFO    1
#define LOGGER_DEBUG   2

#define CONN_STATUS_FLAG_FREE             0
#define CONN_STATUS_FLAG_CONNECTING       1
#define CONN_STATUS_FLAG_ACCEPTING        2
#define CONN_STATUS_FLAG_WAIT_RECV_PASS   4
#define CONN_STATUS_FLAG_WAIT_SEND_PASS   5
#define CONN_STATUS_FLAG_WAIT_VERIFY_PASS 6
#define CONN_STATUS_FLAG_CONNECTED        7
#define CONN_STATUS_FLAG_INACTIVE         8
#define CONN_STATUS_FLAG_INACTIVE_BACKUP  9
#define CONN_STATUS_FLAG_CAN_T_CONNECT    10
#define CONN_STATUS_FLAG_WAIT_FOR_CLOSE   11
#define CONN_STATUS_FLAG_REMOVED          12
#define CONN_STATUS_FLAG_REMOVED_CLEAN    13

#define PKT_TYPE_ETHERNET_ETHFRAME          0
#define PKT_TYPE_ETHERNET_PING              1
#define PKT_TYPE_ETHERNET_PONG              2
#define PKT_TYPE_ETHERNET_PASSWORD          3
#define PKT_TYPE_ETHERNET_ENC_PASSWORD      4
#define PKT_TYPE_ETHERNET_SESSID            5
#define PKT_TYPE_ETHERNET_ENC_SESSID        6
#define PKT_TYPE_ETHERNET_EXTRA_INFO        7
#define PKT_TYPE_ETHERNET_ENC_EXTRA_INFO    8
#define PKT_TYPE_ETHERNET_BACKUP_FREEZE     9
#define PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE 10

#define MAX_PASSWORD_LEN 255
#define MAX_SESSID_LEN   255

#define QUEUE_LAYOUT_INVALID 0
#define QUEUE_LAYOUT_LONG    1
#define QUEUE_LAYOUT_SHORT   2
#define QUEUE_LAYOUT_DEFAULT QUEUE_LAYOUT_SHORT

#define MAX_ENQUEUE_TIME_NS (1000 * 1000)
#define NEEDS_FREE_ENQUEUE 32

#define EXTRA_INFO_STRUCT_VER_UNKNOWN 0
#define EXTRA_INFO_STRUCT_VER_1       1
#define EXTRA_INFO_STRUCT_VER_DEFAULT EXTRA_INFO_STRUCT_VER_1

#define VLAN_OPT_DO_NOTHING    0
#define VLAN_OPT_REMOVE_OUTPUT 1
#define VLAN_OPT_ADD_INPUT     2

#define MAX_VLAN_ID 4096

#define KIT_CRYPT_C_LIB_NAME "kit-crypto-c"

#define VERSION_STR_LEN           16
#define LIB_NAME_STR_LEN          32
#define OS_NAME_STR_LEN           32
#define COMPILATIION_TIME_STR_LEN 256

#define PACKET_RECORD_ENCAP_HRD_SIZE 8

#define BLOCK_SIZE(size_w_checksum) ((size_w_checksum + PACKET_RECORD_ENCAP_HRD_SIZE + 15) & ~0x0F)

#define CONN_ID_NUM(conn_id) ((conn_id & 0xFFFF) - 1)
#define CONN_ID_IDX(conn_id) ((conn_id >> 16) & 0xFFFF)

struct packet_record
{
  int16_t msg_type;
  conn_id_t source;
  conn_id_t destination;
#ifdef PERF_COUNTERS
#define live_start perf_start
  uint64_t perf_start;
#else
  uint64_t live_start;
#endif

  union {
    struct {
      encrypt_key_t encrypt_key;
      checksum_t checksum;
      uint16_t vlan_id;
      uint32_t vlan_mask[MAX_VLAN_ID / 32];
    } conn;
    struct {
      encrypt_key_t key;
      checksum_t checksum;
      uint16_t vlan_id;
      uint16_t vlan_opt;
      uint16_t packet_size;
      conn_id_t bcast_idx;
      uint32_t pkt_idx;
      uint16_t type;
      uint16_t length;
      union {
        struct {
          unsigned char dst_mac[6];
          unsigned char src_mac[6];
          unsigned char proto[4];
          unsigned char data[MAX_MTU - 6 - 6 - 2 - 2 + CHECKSUM_SIZE_MAX];
        } ethframe;
        struct {
          uint8_t pass_length;
          char pass_str[MAX_PASSWORD_LEN];
        } password;
        struct {
          uint8_t sessid_length;
          char sessid_str[MAX_SESSID_LEN];
        } sessid;
        struct {
          uint8_t extra_info_struct_ver;
          char uVPN_version_str[VERSION_STR_LEN];
          char cryptolib_name_str[LIB_NAME_STR_LEN];
          char cryptolib_version_str[VERSION_STR_LEN];
          char os_name_str[OS_NAME_STR_LEN];
          char compilation_time_str[COMPILATIION_TIME_STR_LEN];
        } extra_info;
      };
    } __attribute__((packed)) net;
  };
};

struct tcp_conn_info
{
  conn_id_t conn_id;
  struct tcp_conn_desc_t tcp_conn;
  int auth;
  int incomming;
  volatile unsigned int end_now;
  unsigned char buffer_1[BUFFER_SIZE];
  unsigned char buffer_2[BUFFER_SIZE];
  volatile unsigned char * buffer;
  volatile size_t buffer_fill;
  atomic_uint buffer_sem;
  sem_t write_sem;
  uint64_t written_blocks;
  uint64_t read_blocks;
  uint64_t enc_key[(MAX_CIPHER_KEY_SIZE / 8)];
  uint64_t dec_key[(MAX_CIPHER_KEY_SIZE / 8)];
  uint8_t hmac_in_key[MAX_CHECKSUM_KEY_BYTES];
  uint8_t hmac_out_key[MAX_CHECKSUM_KEY_BYTES];
  volatile unsigned int freeze;
  void * io_read_thread, * io_write_thread, * pass_thread;
  atomic_intptr_t close_thread;
  volatile uint64_t last_read;
  unsigned int timeout[2];
  int mss;
  char name[MAX_CLIENT_NAME_LENGTH];
  char ipstr[64];
  unsigned short port;
  int cipher;
  int checksum;
  size_t limit_output_buffer_size;
  int8_t output_auth_method;
  int flags;
  unsigned int drops_counter;
  uint64_t start_time;
  char send_extra_info;
  uint16_t vlan_id;
  uint32_t vlan_mask[MAX_VLAN_ID / 32];
};

struct tap_conn_info
{
  int dev_sock[TAP_QUEUES];
  uint32_t bcast_counter;

  unsigned char buffer[TAP_BUFFER_SIZE * MAX_MTU * TAP_QUEUES];
  size_t buffer_size[TAP_QUEUES * TAP_BUFFER_SIZE];
  atomic_uint buffer_fill[TAP_QUEUES];
  size_t buffer_start[TAP_QUEUES];
  size_t buffer_end[TAP_QUEUES];

  size_t next_buffer;
  sem_t write_sem[TAP_QUEUES];

  void * io_read_thread;
  void * io_write_thread[TAP_QUEUES];

  uint32_t vlan_mask[MAX_VLAN_ID / 32];
};

extern const unsigned short default_keepalive[2];
extern queue_t global_queue;
extern struct RSA * thiz_rsa;
extern rwmutex_t conns_sem;

extern struct perf_counters perf_counters;

extern char uVPN_version_str[VERSION_STR_LEN];
extern char cryptolib_name_str[LIB_NAME_STR_LEN];
extern char cryptolib_version_str[VERSION_STR_LEN];
extern char os_name_str[OS_NAME_STR_LEN];
extern char compilation_time_str[COMPILATIION_TIME_STR_LEN];

void log_extra_info_strs(const char * prefix, const char * cryptolib_name,
    const char * cryptolib_ver, const char * os_name, const char * ct_str);
int is_mcast(unsigned char * mac);
int sem_wait_int(sem_t *sem, volatile unsigned int * local_end_now);
