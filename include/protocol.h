#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAGIC_NUMBER 0xDEEBB1F         // magic number so client knows
#define VERSION 1.0                    // program version
#define PACKET_TYPE 1 // temp will change when other types are added

#define tlv_struct_32(name) struct { uint8_t t; uint16_t l; uint32_t v; } name
#define tlv_struct_16(name) struct { uint8_t t; uint16_t l; uint16_t v; } name
#define tlv_struct_char(name, size) struct {uint8_t t; uint16_t l; char v[size]; } name

typedef enum {
    PID_TYPE,
    COMM_TYPE,
    STATE_TYPE,
    PPID_TYPE,
    CPU_TYPE,
    MEM_TYPE,
    START_TYPE,
    FILE_SIZE_TYPE,
    EXE_TYPE,
    FLAGS_TYPE,
    ACCESS_TYPE,
    MODIFIED_TYPE,
    STATUS_TYPE,
    FILE_MODE_TYPE

} tlv_type;

struct packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t packet_type;               // type of packet...make macros for different ones...
    uint32_t time_stamp;                // not sure if this goes here???
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version

} __attribute__((packed));

// struct tlv_t {

//     uint8_t tag;                        // what the data is like pid or comm or last_access...
//     uint16_t length;                    // length of data

//     union {
//         char     string[256];           // for exe path or comm
//         uint32_t u32;                   // for pid, ppid, times
//         uint16_t u16;                   // for cpu/mem usage
//         uint8_t  u8;                    // for flags/state byte
//     } value;

// } __attribute__((packed));

#endif // !PROTOCOL_H
