#ifndef STRUCT_DEF
#define STRUCT_DEF

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

// my attempt at making "DEEP BIN in hexspeak"
// for the project name of "binmon/ binary monitor"
// should probably change in the future though
#define MAGIC_NUMBER 0xDEEBB1F

#define DELTA_PROGRAM 1             // tick rate of the program
#define RESIZE_PERCENTAGE .90       // What percent full until resizing
#define DEFAULT_OLD 2592000         // how many days in seconds until a process is old(30 days)
#define DEFAULT_MAX 1024            // default size of max procs before relloc
#define STATS_LENGTH 256            // lenght of stats of each process
#define PORT 9000                   // port where client is listening on
#define SERVER_ADDRESS "127.0.0.1"  // server address... localhost for now

struct __attribute__((packed)) packet_header {

    uint32_t magic_number;              // so client knows its this data
    uint32_t payload_length;            // length whole buffer
    uint32_t sequence;                  // order of the packet
    uint32_t crc;                       // checksum value for packet
    uint16_t version;                   // protocol version
};

typedef struct {
    uint8_t tag;                        // what the data is like pid or comm or last_access...
    uint16_t length;                    // length of data

    union {
        char     string[256];           // for exe path or comm
        uint32_t u32;                   // for pid, ppid, times
        uint16_t u16;                   // for cpu/mem usage
        uint8_t  u8;                    // for flags/state byte
    } value;

} tlv_t;

typedef struct {
    // think of more to add
    uint8_t     state        : 4;       // state can be from 0 to 15 so 4 bits are needed
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;       // only used for finding new processes

} proc_flags_t;

typedef struct {
    char                *exe_path;      // Binary path
    const char          *comm;          // process name

    uint32_t            last_access;    // time last accessed
    uint32_t            last_modified;  // time last modified
    uint32_t            last_status;    // time last status change
    uint32_t            pid;            // proccess id
    uint32_t            ppid;           // parent process id

    uint16_t            first_seen;     // first seen time thats persistant
                                        //  see if theres a field that indicates
                                        //  the very first time it was seen instead
                                        //
    uint16_t            cpu_usage;      // current cpu usage
    uint16_t            mem_usage;      // current mem usage
    uint16_t            start_time;     // time if process started in current session
    uint16_t            file_size;      // size of file in bytes
    proc_flags_t        flags_table;    // Bitfield location
} proc_data_t;

struct proc_info {
    proc_data_t         *data;          // array of proc_data_t's
    u_int32_t           proc_count;     // total processes tracked
    u_int32_t           capacity;       // allocated size
    u_int32_t           sequence;       // packet sequence state
    u_int32_t           tlv_size;       // total size of tlvs
};

// void check_capacity(struct proc_info *p_info);
void scan_data(struct proc_info *p_info);
void pack_data(struct proc_info *p_info, char *network_buffer);
void send_data(struct proc_info *p_info, char *network_buffer);
void get_log_time(char *buffer, size_t length);

#endif // STRUCT_DEF
