/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "checksum.h"
#include <stdio.h>
#include <string.h>
#include <logger.h>
#include <clock.h>
#include <kitcryptoc/sha2.h>
#include <kitcryptoc/sha2_hmac.h>

#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

static int checksum_sha224_check(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA224];

  kit_sha224(sha, data, normal_size);

  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA224) == 0;
}

static int checksum_sha256_check(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA256];

  kit_sha256(sha, data, normal_size);

  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA256) == 0;
}

static int checksum_sha384_check(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA384];

  kit_sha384(sha, data, normal_size);
  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA384) == 0;
}

static int checksum_sha512_check(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA512];

  kit_sha512(sha, data, normal_size);
  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA512) == 0;
}

static int checksum_sha224_hmac_check(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA224];

  kit_sha224_hmac(sha, data, normal_size, key, KIT_SHA256_WORK_BLOCK_SIZE);

  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA224) == 0;
}

static int checksum_sha256_hmac_check(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA256];

  kit_sha256_hmac(sha, data, normal_size, key, KIT_SHA256_WORK_BLOCK_SIZE);

  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA256) == 0;
}

static int checksum_sha384_hmac_check(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA384];

  kit_sha384_hmac(sha, data, normal_size, key, KIT_SHA512_WORK_BLOCK_SIZE);
  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA384) == 0;
}

static int checksum_sha512_hmac_check(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;
  unsigned char sha[CHECKSUM_SIZE_SHA512];

  kit_sha512_hmac(sha, data, normal_size, key, KIT_SHA512_WORK_BLOCK_SIZE);
  return memcmp(&data[normal_size], sha, CHECKSUM_SIZE_SHA512) == 0;
}

void checksum_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

#ifdef PERF_COUNTERS
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();

    atomic_fetch_add(&perf_counters.pkg_process_to_checksum,
        time1 - data->perf_start);
    atomic_fetch_add(&perf_counters.pkg_process_to_checksum_ctr, 1);
  }
#endif

  unsigned char * rawdata = (unsigned char *)&data->net.ethframe.dst_mac;
  uint16_t length = data->net.packet_size;

  if (data->net.checksum.type == CHECKSUM_NONE) {
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.checksum, time2 - time1);
      atomic_fetch_add(&perf_counters.checksum_ctr, 1);
    }
#endif
    return;
  }

  if (data->net.checksum.type == CHECKSUM_SHA224) {
    if (!checksum_sha224_check(rawdata, length)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha224) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA256) {
    if (!checksum_sha256_check(rawdata, length)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha256) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA384) {
    if (!checksum_sha384_check(rawdata, length)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha384) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA512) {
    if (!checksum_sha512_check(rawdata, length)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha512) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA224_HMAC) {
    if (!checksum_sha224_hmac_check(rawdata, length, data->net.checksum.key)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha224hmac) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA256_HMAC) {
    if (!checksum_sha256_hmac_check(rawdata, length, data->net.checksum.key)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha256hmac) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA384_HMAC) {
    if (!checksum_sha384_hmac_check(rawdata, length, data->net.checksum.key)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha384hmac) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  } else if (data->net.checksum.type == CHECKSUM_SHA512_HMAC) {
    if (!checksum_sha512_hmac_check(rawdata, length, data->net.checksum.key)) {
      logger_printf(LOGGER_ERROR, "Drop packet from "
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (sha512hmac) %zu",
        data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
        data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
        data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
        length);
      data->msg_type = MSG_TYPE_CHECKSUM_DROP;
      data->destination = data->source;
    }
  }

#ifdef PERF_COUNTERS
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.checksum, time2 - time1);
    atomic_fetch_add(&perf_counters.checksum_ctr, 1);
  }
#endif
}
