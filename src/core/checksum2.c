/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "checksum2.h"
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

void checksum_sha224_calc(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;

  kit_sha224(&data[normal_size], data, normal_size);
}

void checksum_sha256_calc(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;

  kit_sha256(&data[normal_size], data, normal_size);
}

void checksum_sha384_calc(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;

  kit_sha384(&data[normal_size], data, normal_size);
}

void checksum_sha512_calc(unsigned char * data, size_t data_size)
{
  size_t normal_size = data_size;

  kit_sha512(&data[normal_size], data, normal_size);
}

void checksum_sha224_hmac_calc(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;

  kit_sha224_hmac(&data[normal_size], data, normal_size, key,
      KIT_SHA256_WORK_BLOCK_SIZE);
}

void checksum_sha256_hmac_calc(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;

  kit_sha256_hmac(&data[normal_size], data, normal_size, key,
      KIT_SHA256_WORK_BLOCK_SIZE);
}

void checksum_sha384_hmac_calc(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;

  kit_sha384_hmac(&data[normal_size], data, normal_size, key,
      KIT_SHA512_WORK_BLOCK_SIZE);
}

void checksum_sha512_hmac_calc(unsigned char * data, size_t data_size,
  const uint8_t * key)
{
  size_t normal_size = data_size;

  kit_sha512_hmac(&data[normal_size], data, normal_size, key,
      KIT_SHA512_WORK_BLOCK_SIZE);
}

void checksum2_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

#ifdef PERF_COUNTERS
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();

    atomic_fetch_add(&perf_counters.pkg_process_to_checksum2,
        time1 - data->perf_start);
    atomic_fetch_add(&perf_counters.pkg_process_to_checksum2_ctr, 1);
  }
#endif

  unsigned char * rawdata = (unsigned char *)&data->net.ethframe.dst_mac;
  uint16_t length = data->net.packet_size;

  if ((data->net.checksum.type == CHECKSUM_NONE) ||
      (data->destination == TAP_CONN_ID)) {
#ifdef PERF_COUNTERS
    if (perf_counters.interval > 0) {
      time2 = getnow_monotonic();
      atomic_fetch_add(&perf_counters.checksum2, time2 - time1);
      atomic_fetch_add(&perf_counters.checksum2_ctr, 1);
    }
#endif
    return;
  }

  if (data->net.checksum.type == CHECKSUM_SHA224) {
    checksum_sha224_calc(rawdata, length);
  } else if (data->net.checksum.type == CHECKSUM_SHA256) {
    checksum_sha256_calc(rawdata, length);
  } else if (data->net.checksum.type == CHECKSUM_SHA384) {
    checksum_sha384_calc(rawdata, length);
  } else if (data->net.checksum.type == CHECKSUM_SHA512) {
    checksum_sha512_calc(rawdata, length);
  } else if (data->net.checksum.type == CHECKSUM_SHA224_HMAC) {
    checksum_sha224_hmac_calc(rawdata, length, data->net.checksum.key);
  } else if (data->net.checksum.type == CHECKSUM_SHA256_HMAC) {
    checksum_sha256_hmac_calc(rawdata, length, data->net.checksum.key);
  } else if (data->net.checksum.type == CHECKSUM_SHA384_HMAC) {
    checksum_sha384_hmac_calc(rawdata, length, data->net.checksum.key);
  } else if (data->net.checksum.type == CHECKSUM_SHA512_HMAC) {
    checksum_sha512_hmac_calc(rawdata, length, data->net.checksum.key);
  }

  data->net.checksum.type &= 0x7FFF;

#ifdef PERF_COUNTERS
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.checksum2, time2 - time1);
    atomic_fetch_add(&perf_counters.checksum2_ctr, 1);
  }
#endif
}
