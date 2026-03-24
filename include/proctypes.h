#ifndef MAIN_STRUCT_H
#define MAIN_STRUCT_H

#include "logging.h"
#include <stdint.h>
#include <sys/types.h>

#define VERSION 1.0             // program version
#define DELTA_PROGRAM 1         // tick rate of the program
#define RESIZE_PERCENTAGE .90   // What percent full until resizing
#define DEFAULT_OLD 2592000     // how many days in seconds until a process is old(30 days)
#define DEFAULT_MAX 1024        // default size of max procs before relloc
#define STATS_LENGTH 256        // lenght of stats of each process

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
    u_int32_t           total_tlv_size; // total size of tlvs
    u_int32_t           total_ph_size;  // total size of packet header
};

extern int g_finished;
extern int g_logging;

void scan_data(struct proc_info *p_info);
void pack_data(struct proc_info *p_info, char *data_buffer);
void pack_header(struct proc_info *p_info, char *packet_buffer);
void send_packet(struct proc_info *p_info, char *data_buffer, char *header_buffer);

#endif // MAIN_STRUCT_H
