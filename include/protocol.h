#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAGIC_NUMBER 0xDEEBB1F      // magic number so client knows
#define PORT 9000                   // port where client is listening on
#define SERVER_ADDRESS "127.0.0.1"  // server address (this is the server)

// __attribute__((packed)) for no padding
// as this data will be sent over a network

struct __attribute__((packed)) packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version
};

typedef struct __attribute__((packed)) {

    uint8_t tag;                        // what the data is like pid or comm or last_access...
    uint16_t length;                    // length of data

    union {
        char     string[256];           // for exe path or comm
        uint32_t u32;                   // for pid, ppid, times
        uint16_t u16;                   // for cpu/mem usage
        uint8_t  u8;                    // for flags/state byte
    } value;

} tlv_t;

#endif // !PROTOCOL_H
