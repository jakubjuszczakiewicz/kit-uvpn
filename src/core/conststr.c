/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "conststr.h"
#include <string.h>

int cipher_mode_str_to_int(const char * cipher)
{
  if (!cipher)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish:mixed") == 0)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish") == 0)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish:ctr") == 0)
    return CIPHER_TYPE_TWOFISH_CTR;
  if (strcmp(cipher, "aes:mixed") == 0)
    return CIPHER_TYPE_AES_MIXED;
  if (strcmp(cipher, "aes") == 0)
    return CIPHER_TYPE_AES_MIXED;
  if (strcmp(cipher, "aes:ctr") == 0)
    return CIPHER_TYPE_AES_CTR;
  if (strcmp(cipher, "null") == 0)
    return CIPHER_TYPE_NULL;
  if (strcmp(cipher, "none") == 0)
    return CIPHER_TYPE_NULL;
  return -1;
}

size_t get_key_size(int cipher)
{
  if (cipher == CIPHER_TYPE_TWOFISH_CTR)
    return CIPHER_KEY_SIZE_TWOFISH_CTR;

  if (cipher == CIPHER_TYPE_AES_CTR)
    return CIPHER_KEY_SIZE_AES_CTR;

  if (cipher == CIPHER_TYPE_AES_MIXED)
    return CIPHER_KEY_SIZE_AES_MIXED;

  return CIPHER_KEY_SIZE_TWOFISH_MIXED;
}

int checksum_str_to_int(const char * checksum)
{
  if (!checksum)
    return CHECKSUM_NONE;
  if (strcmp(checksum, "none") == 0)
    return CHECKSUM_NONE;
  if (strcmp(checksum, "null") == 0)
    return CHECKSUM_NONE;
  if (strcmp(checksum, "sha224") == 0)
    return CHECKSUM_SHA224;
  if (strcmp(checksum, "sha256") == 0)
    return CHECKSUM_SHA256;
  if (strcmp(checksum, "sha384") == 0)
    return CHECKSUM_SHA384;
  if (strcmp(checksum, "sha512") == 0)
    return CHECKSUM_SHA512;
  if (strcmp(checksum, "sha224hmac") == 0)
    return CHECKSUM_SHA224_HMAC;
  if (strcmp(checksum, "sha256hamc") == 0)
    return CHECKSUM_SHA256_HMAC;
  if (strcmp(checksum, "sha384hmac") == 0)
    return CHECKSUM_SHA384_HMAC;
  if (strcmp(checksum, "sha512hmac") == 0)
    return CHECKSUM_SHA512_HMAC;

  return -1;
}

size_t get_checksum_size(int checksum)
{
  switch (checksum) {
    case CHECKSUM_NONE:
      return CHECKSUM_SIZE_NONE;
    case CHECKSUM_SHA224:
      return CHECKSUM_SIZE_SHA224;
    case CHECKSUM_SHA256:
      return CHECKSUM_SIZE_SHA256;
    case CHECKSUM_SHA384:
      return CHECKSUM_SIZE_SHA384;
    case CHECKSUM_SHA512:
      return CHECKSUM_SIZE_SHA512;
    case CHECKSUM_SHA224_HMAC:
      return CHECKSUM_SIZE_SHA224_HMAC;
    case CHECKSUM_SHA256_HMAC:
      return CHECKSUM_SIZE_SHA256_HMAC;
    case CHECKSUM_SHA384_HMAC:
      return CHECKSUM_SIZE_SHA384_HMAC;
    case CHECKSUM_SHA512_HMAC:
      return CHECKSUM_SIZE_SHA512_HMAC;
    default:
      return 0;
  }
}

size_t get_checksum_hmac_key_size(int checksum)
{
  switch (checksum) {
    case CHECKSUM_NONE:
      return 0;
    case CHECKSUM_SHA224:
      return 0;
    case CHECKSUM_SHA256:
      return 0;
    case CHECKSUM_SHA384:
      return 0;
    case CHECKSUM_SHA512:
      return 0;
    case CHECKSUM_SHA224_HMAC:
      return CHECKSUM_SHA224_HAMC_KEY_SIZE;
    case CHECKSUM_SHA256_HMAC:
      return CHECKSUM_SHA256_HAMC_KEY_SIZE;
    case CHECKSUM_SHA384_HMAC:
      return CHECKSUM_SHA384_HAMC_KEY_SIZE;
    case CHECKSUM_SHA512_HMAC:
      return CHECKSUM_SHA512_HAMC_KEY_SIZE;
    default:
      return 0;
  }
}


int dict_alg_str_to_int(const char * dict_alg)
{
  if (!dict_alg)
    return DICT_ALGORITHM_AVL_16;
  if (strcmp(dict_alg, "avl16") == 0)
    return DICT_ALGORITHM_AVL_16;
  if (strcmp(dict_alg, "avl24") == 0)
    return DICT_ALGORITHM_AVL_24;
  if (strcmp(dict_alg, "hashtab16") == 0)
    return DICT_ALGORITHM_HASHTAB_16;
  if (strcmp(dict_alg, "hashtab24") == 0)
    return DICT_ALGORITHM_HASHTAB_24;

  return -1;
}

int conn_mode_str_to_int(const char * mode)
{
  if (!mode)
    return CONN_MODE_NORMAL;
  if (strcmp(mode, "normal") == 0)
    return CONN_MODE_NORMAL;
  if (strcmp(mode, "offline backup") == 0)
    return CONN_MODE_OFFLINE_BACKUP;
  if (strcmp(mode, "active backup") == 0)
    return CONN_MODE_ACTIVE_BACKUP;
  if (strcmp(mode, "removed") == 0)
    return CONN_MODE_REMOVED;

  return -1;
}

const char * conn_status_flag_to_str(unsigned int flags)
{
  switch (flags) {
    case CONN_STATUS_FLAG_FREE:
      return "free";
    case CONN_STATUS_FLAG_CONNECTING:
      return "connecting";
    case CONN_STATUS_FLAG_ACCEPTING:
      return "accepting";
    case CONN_STATUS_FLAG_WAIT_RECV_PASS:
      return "wait for reveice pass";
    case CONN_STATUS_FLAG_WAIT_SEND_PASS:
      return "wait for send pass";
    case CONN_STATUS_FLAG_WAIT_VERIFY_PASS:
      return "wait verify pass";
    case CONN_STATUS_FLAG_CONNECTED:
      return "connected";
    case CONN_STATUS_FLAG_INACTIVE:
      return "inactive";
    case CONN_STATUS_FLAG_INACTIVE_BACKUP:
      return "inactive (backup)";
    case CONN_STATUS_FLAG_CAN_T_CONNECT:
      return "can't connect";
    case CONN_STATUS_FLAG_WAIT_FOR_CLOSE:
      return "wait for close";
    case CONN_STATUS_FLAG_REMOVED:
      return "removed";
    case CONN_STATUS_FLAG_REMOVED_CLEAN:
      return "wait for clean (removed)";
    default:
      return "";
  };
}

int queue_layout_str_to_int(const char * queue_layout)
{
  if (!queue_layout)
    return QUEUE_LAYOUT_DEFAULT;
  if (strcmp(queue_layout, "long") == 0)
    return QUEUE_LAYOUT_LONG;
  if (strcmp(queue_layout, "short") == 0)
    return QUEUE_LAYOUT_SHORT;
  return QUEUE_LAYOUT_INVALID;
}
