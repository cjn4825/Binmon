#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

struct packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version

} __attribute__((packed));

struct tlv_t {

    uint8_t tag;                        // what the data is like pid or comm or last_access...
    uint16_t length;                    // length of data

    union {
        char     string[256];           // for exe path or comm
        uint32_t u32;                   // for pid, ppid, times
        uint16_t u16;                   // for cpu/mem usage
        uint8_t  u8;                    // for flags/state byte
    } value;

} __attribute__((packed));

#endif // !PROTOCOL_H
