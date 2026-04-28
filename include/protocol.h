#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

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
