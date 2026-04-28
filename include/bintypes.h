#ifndef BIN_STRUCT_H
#define BIN_STRUCT_H

#include "logging.h"
#include "thread.h"
#include <stdint.h>
#include <sys/types.h>

struct bin_flags_t{
    // think of more to add
    uint8_t     state        : 4;       // state can be from 0 to 15 so 4 bits are needed
    uint8_t     is_old       : 1;
    uint8_t     not_missing  : 1;       // only used for finding new processes

};

struct bin_data_t{
    char                   *exe_path;      // Binary path
    char                   *comm;          // process name

    uint32_t               last_access;    // time last accessed
    uint32_t               last_modified;  // time last modified
    uint32_t               last_status;    // time last status change
    uint32_t               pid;            // proccess id
    uint32_t               ppid;           // parent process id

    uint16_t               first_seen;     // first seen time thats persistant
                                           //  see if theres a field that indicates
                                           //  the very first time it was seen instead

    uint16_t               cpu_usage;      // current cpu usage
    uint16_t               mem_usage;      // current mem usage
    uint16_t               start_time;     // time if process started in current session
    uint16_t               file_size;      // size of file in bytes
    struct bin_flags_t    flags_table;    // Bitfield location
};

struct proc_bin_t {
    struct bin_data_t     *data;          // pointer to data
                                          // type?
    u_int32_t              size;       // size of data
};

void update_bins(struct thread_context_t *context);
void pack_data(struct thread_context_t *context);
void pack_header(struct thread_context_t *context);
// void send_packet(struct thread_context_t *context, int type);

#endif // !BIN_STRUCT_H
