#ifndef MAIN_STRUCT_H
#define MAIN_STRUCT_H

#include "logging.h"
#include "thread.h"
#include <stdint.h>
#include <sys/types.h>

struct packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t type;                      // type of packet...make macros for different ones...
    uint32_t time_stamp;                // not sure if this goes here???
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version

} __attribute__((packed));

struct proc_flags_t{
    // think of more to add
    uint8_t     state        : 4;       // state can be from 0 to 15 so 4 bits are needed
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;       // only used for finding new processes

} __attribute__((packed));

struct proc_data_t{
    struct packet_header   header;
    // find a way to change char size to optimize the size
    struct {uint8_t t; uint16_t l; char v[256]; } exe_path;
    struct {uint8_t t; uint16_t l; char v[256]; } comm;
    struct {uint8_t t; uint16_t l; uint32_t v; } last_access;
    struct {uint8_t t; uint16_t l; uint32_t v; } last_modified;
    struct {uint8_t t; uint16_t l; uint32_t v; } last_status;
    struct {uint8_t t; uint16_t l; uint32_t v; } pid;
    struct {uint8_t t; uint16_t l; uint32_t v; } ppid;
    struct {uint8_t t; uint16_t l; uint16_t v; } first_seen;

                                           // first seen time thats persistant
                                           //  see if theres a field that indicates
                                           //  the very first time it was seen instead

    struct {uint8_t t; uint16_t l; uint16_t v; } cpu_usage;
    struct {uint8_t t; uint16_t l; uint16_t v; } mem_usage;
    struct {uint8_t t; uint16_t l; uint16_t v; } start_time;
    struct {uint8_t t; uint16_t l; uint16_t v; } file_size;
    struct {uint8_t t; uint16_t l; typedef struct proc_flags_t v; } flags_table;
} __attribute__((packed)); // see if this is right... tryp to replace structs with macro function?

void scan_procs(struct thread_context_t *context);
void update_bins(struct thread_context_t *context);
void pack_data(struct thread_context_t *context);
void pack_header(struct thread_context_t *context, void *proc_header_loc);
void send_packet(struct thread_context_t *context, int type);

#endif // !MAIN_STRUCT_H
