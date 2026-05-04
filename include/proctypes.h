#ifndef MAIN_STRUCT_H
#define MAIN_STRUCT_H

#include <stdint.h>

#include "../include/protocol.h"

struct proc_flags_t {
    // think of more to add
    uint8_t     state        : 4;       // state can be from 0 to 15 so 4 bits are needed
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;       // only used for finding new processes

} __attribute__((packed));

struct proc_data_t {

    struct packet_header header;

    // find a way to change char size to optimize the size...
    // for now this is ok...also should split to hot and cold data for cpu cache locality
    tlv_struct_char(exe_path, 256);
    tlv_struct_char(comm, 256);

    tlv_struct_32(last_access);
    tlv_struct_32(last_modified);
    tlv_struct_32(last_status);
    tlv_struct_32(pid);
    tlv_struct_32(ppid);

    tlv_struct_16(first_seen);
    tlv_struct_16(cpu_usage);
    tlv_struct_16(mem_usage);
    tlv_struct_16(start_time);
    tlv_struct_16(file_size);

    struct { uint8_t t; uint16_t l; struct proc_flags_t v; } proc_flags;

} __attribute__((packed));

void scan_procs(void *offset_loc);
void pack_header(struct thread_context_t *context, void *proc_header_loc);
void send_packet(struct thread_context_t *context, int type);

#endif // !MAIN_STRUCT_H
