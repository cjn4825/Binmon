#ifndef BIN_STRUCT_H
#define BIN_STRUCT_H

#include <stdint.h>
#include <sys/types.h>

#include "../include/protocol.h"

struct bin_flags_t {
    // think of more to add
    uint8_t     is_old       : 1;

} __attribute__((packed));

struct bin_data_t {
    struct packet_header header;

    // find a way to change char size to optimize the size...
    // for now this is ok...also should split to hot and cold data for cpu cache locality
    tlv_struct_char(exe_path, 256);
    tlv_struct_char(comm, 256);

    tlv_struct_32(last_access);
    tlv_struct_32(last_status);
    tlv_struct_32(last_modified);
    tlv_struct_32(file_mode);

    tlv_struct_16(first_seen);
    tlv_struct_16(file_size);

    struct { uint8_t t; uint16_t l; struct bin_flags_t v; } bin_flags;
} __attribute__((packed));

void scan_bins(void *offset_loc);

#endif // !BIN_STRUCT_H
