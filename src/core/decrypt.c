/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "decrypt.h"
#include <string.h>
#include "conststr.h"
#include <clock.h>
#include <kitcryptoc/twofish.h>
#include <kitcryptoc/aes.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

void decrypt_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  if (data->msg_type != MSG_TYPE_ENC_NET)
    return;

#ifdef PERF_COUNTERS 
  uint64_t time1 = 0, time2;
  if (perf_counters.interval > 0) {
    time1 = getnow_monotonic();

    atomic_fetch_add(&perf_counters.pkg_process_to_decrypt,
        time1 - data->perf_start);
    atomic_fetch_add(&perf_counters.pkg_process_to_decrypt_ctr, 1);
  }
#endif

  data->msg_type = MSG_TYPE_RAW_NET;

  uint64_t key[4];
  memcpy(key, data->net.key.key, sizeof(key));
  memset(data->net.key.key, 0, sizeof(data->net.key.key));

  unsigned char * encdata = (unsigned char *)&data->net.pkt_idx;
  uint16_t length = data->net.packet_size +
      get_checksum_size(data->net.checksum.type);
  uint32_t blocks = BLOCK_SIZE(length);

  if (data->net.key.type == CIPHER_TYPE_TWOFISH_MIXED) {
    kit_twofish_key tf_key;

    for (uint16_t i = 0; i < blocks; i += 16, encdata += 16) {
      kit_twofish_init_128(&tf_key, (unsigned char *)key);

      key[0] ^= *(uint64_t *)encdata;
      key[1] ^= *(((uint64_t *)encdata) + 1);

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);

      kit_twofish_decrypt_block(&tf_key, encdata, encdata);
    }
  } else if (data->net.key.type == CIPHER_TYPE_TWOFISH_CTR) {
    kit_twofish_key tf_key;
    kit_twofish_init_128(&tf_key, (unsigned char *)&key[2]);
    uint64_t tmp[2];

    for (uint16_t i = 0; i < blocks; i += 16, encdata += 16) {
      kit_twofish_encrypt_block(&tf_key, (unsigned char *)tmp,
          (unsigned char *)key);

      *(uint64_t *)encdata ^= tmp[0];
      *(((uint64_t *)encdata) + 1) ^= tmp[1];

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  } else if (data->net.key.type == CIPHER_TYPE_AES_MIXED) {
    kit_aes_key aes_key;

    for (uint16_t i = 0; i < blocks; i += 16, encdata += 16) {
      kit_aes_init_128(&aes_key, (unsigned char *)key);

      key[0] ^= *(uint64_t *)encdata;
      key[1] ^= *(((uint64_t *)encdata) + 1);

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);

      kit_aes_decrypt_block(&aes_key, encdata, encdata);
    }
  } else if (data->net.key.type == CIPHER_TYPE_AES_CTR) {
    kit_aes_key aes_key;
    kit_aes_init_128(&aes_key, (unsigned char *)&key[2]);
    uint64_t tmp[2];

    for (uint16_t i = 0; i < blocks; i += 16, encdata += 16) {
      kit_aes_encrypt_block(&aes_key, (unsigned char *)tmp,
          (unsigned char *)key);

      *(uint64_t *)encdata ^= tmp[0];
      *(((uint64_t *)encdata) + 1) ^= tmp[1];

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  }

  data->net.key.type = -1;

  if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_PASSWORD)
    data->net.type = htobe16(PKT_TYPE_ETHERNET_PASSWORD);
  else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_SESSID)
    data->net.type = htobe16(PKT_TYPE_ETHERNET_SESSID);
  else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_EXTRA_INFO)
    data->net.type = htobe16(PKT_TYPE_ETHERNET_EXTRA_INFO);
  else if (be16toh(data->net.type) == PKT_TYPE_ETHERNET_ENC_BACKUP_FREEZE)
    data->net.type = htobe16(PKT_TYPE_ETHERNET_BACKUP_FREEZE);

#ifdef PERF_COUNTERS 
  if (perf_counters.interval > 0) {
    time2 = getnow_monotonic();
    atomic_fetch_add(&perf_counters.decrypt, time2 - time1);
    atomic_fetch_add(&perf_counters.decrypt_ctr, 1);
  }
#endif
}
