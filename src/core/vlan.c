/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "vlan.h"
#include <string.h>
#include "conststr.h"
#include <logger.h>

void vlan_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

  uint16_t length = data->net.packet_size +
      get_checksum_size(data->net.checksum.type);

  if (data->net.vlan_opt == VLAN_OPT_ADD_INPUT) {
    if (((data->net.ethframe.proto[0] << 8) + data->net.ethframe.proto[1])
          != VLAN_PROTO_ID) {
      logger_printf(LOGGER_DEBUG, "[VLAN] Add VLAN:"
          " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (%hu %hd)",
          data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
          data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
          data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
          data->net.vlan_id, data->source, data->destination);
      memmove(&data->net.ethframe.proto[4], data->net.ethframe.proto, length);
      data->net.ethframe.proto[0] = VLAN_PROTO_ID >> 8;
      data->net.ethframe.proto[1] = VLAN_PROTO_ID & 0xFF;
      data->net.ethframe.proto[2] = data->net.vlan_id >> 8;
      data->net.ethframe.proto[3] = data->net.vlan_id & 0xFF;
      data->net.vlan_opt = VLAN_OPT_DO_NOTHING;
      data->net.vlan_id = 0;
      data->net.packet_size += 4;
      data->net.length = htobe16(be16toh(data->net.length) + 4);
    }
  }
}

void vlan2_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

  uint16_t length = data->net.packet_size +
      get_checksum_size(data->net.checksum.type);

  uint16_t vlan = data->net.vlan_id;

  if (data->net.vlan_opt == VLAN_OPT_REMOVE_OUTPUT) {
    if (((data->net.ethframe.proto[0] << 8) + data->net.ethframe.proto[1])
          == VLAN_PROTO_ID) {
      logger_printf(LOGGER_DEBUG, "Remove VLAN:"
          " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (vlan: %hu) (%hu %hu)",
          data->net.ethframe.src_mac[0], data->net.ethframe.src_mac[1],
          data->net.ethframe.src_mac[2], data->net.ethframe.src_mac[3],
          data->net.ethframe.src_mac[4], data->net.ethframe.src_mac[5],
          vlan, data->source, data->destination);
      memmove(data->net.ethframe.proto, &data->net.ethframe.proto[4],
          length);
      data->net.packet_size -= 4;
      data->net.length = htobe16(data->net.packet_size);
      data->net.vlan_opt = VLAN_OPT_DO_NOTHING;
      data->net.vlan_id = vlan;
      data->net.checksum.type &= 0x7FFF;
    }
  }
}
