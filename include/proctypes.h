#ifndef MAIN_STRUCT_H
#define MAIN_STRUCT_H

#include <stdint.h>

#define MAGIC_NUMBER 0xDEEBB1F         // magic number so client knows
#define VERSION 1.0                    // program version

struct packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t packet_type;               // type of packet...make macros for different ones...
    uint32_t time_stamp;                // not sure if this goes here???
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version

} __attribute__((packed));

struct proc_flags_t {
    // think of more to add
    uint8_t     state        : 4;       // state can be from 0 to 15 so 4 bits are needed
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;       // only used for finding new processes

} __attribute__((packed));

#define tlv_struct_32(name) struct { uint8_t t; uint16_t l; uint32_t v; } name
#define tlv_struct_16(name) struct { uint8_t t; uint16_t l; uint16_t v; } name
#define tlv_struct_char(name, size) struct {uint8_t t; uint16_t l; char v[size]; } name

struct proc_data_t {

    struct packet_header header; // not sure if i need to init this and flags...

    // find a way to change char size to optimize the size
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

    struct {uint8_t t; uint16_t l; struct proc_flags_t v; } flags_table;

} __attribute__((packed));

#define PACKET_TYPE 1 // temp will change when other types are added

void scan_procs(void *offset_loc);
void update_bins(struct thread_context_t *context);
void pack_data(struct thread_context_t *context);
void pack_header(struct thread_context_t *context, void *proc_header_loc);
void send_packet(struct thread_context_t *context, int type);

#endif // !MAIN_STRUCT_H
