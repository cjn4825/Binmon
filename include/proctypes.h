#ifndef STRUCT_DEF
#define STRUCT_DEF

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

// my attempt at making "Deep bin mon in hexspeak"
#define MAGIC_NUMBER 0xDEEBB1FE0F

#define DELTA_PROGRAM 100000        // How many times the program refreshes
#define RESIZE_PERCENTAGE .90       // What percent full until resizing
#define DELTA_SCAN 0.5              // How many seconds a scan happens
#define DEFAULT_MAX 1024            // default max until reallocating is needed
#define DEFAULT_OLD 2592000         // how many days in seconds until a process is old(30 days)

struct packet_header {
    uint32_t magic_number;          // so client knows its this data
    uint32_t version;               // protocol version
    uint32_t payload_length;        // length whole buffer
} __attribute__((packed));

typedef struct {
    uint8_t tag;                    // what the data is like pid or comm or last_access...
    uint16_t length;                // length of data

    union {
        uint32_t u32;               // for pid, ppid, times
        uint16_t u16;               // for cpu/mem usage
        uint8_t  u8;                // for flags/state byte
        char     string[256];       // for exe path or comm
    } value;

} tlv_t;

typedef struct {
    uint16_t cpu_usage_1;           // historical view to find average cpu
    uint16_t cpu_usage_2;
    uint16_t cpu_usage_3;
    uint16_t cpu_usage_4;
    uint16_t cpu_usage_5;
} proc_cpu_usage_t;

typedef struct {
    uint16_t mem_usage_1;           // historical view to find average mem
    uint16_t mem_usage_2;
    uint16_t mem_usage_3;
    uint16_t mem_usage_4;
    uint16_t mem_usage_5;
} proc_mem_usage_t;

typedef struct {
    uint8_t     cpu_up       : 1;    // 1 bit for cpu usage and others
    uint8_t     mem_up       : 1;
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;
    uint8_t     state        : 4;    // state can be from 0 to 15 so 4 bits are needed

} proc_flags_t;

typedef struct {
    char                *exe_path;      // Binary path
    const char          *comm;          // process name
    proc_cpu_usage_t    *cpu_table;     // cpu usage table
    proc_mem_usage_t    *mem_table;     // mem usage table

    uint32_t            last_access;    // time last accessed
    uint32_t            last_modified;  // time last modified
    uint32_t            pid;            // proccess id
    uint32_t            ppid;           // parent process id

    uint16_t            first_seen;     // first seen time thats persistant
    uint16_t            cpu_usage;      // current cpu usage
    uint16_t            mem_usage;      // current mem usage
    uint16_t            start_time;     // time if process started in current session
    proc_flags_t        flags_table;    // Bitfield location
} proc_data_t;

struct proc_info {
    proc_data_t         *data;          // array of proc_data_t's
    u_int32_t           proc_count;     // total processes tracked
    u_int32_t           capacity;       // allocated size
};

void update_capacity(struct proc_info *p_info);
void save_state(struct proc_info *p_info);
void scan_procs(struct proc_info *p_info);
void load_state(struct proc_info *p_info);
void get_log_time(char *buffer, size_t length);

#endif // STRUCT_DEF
