#ifndef STRUCT_DEF
#define STRUCT_DEF

#include <sys/types.h>
#include <stdbool.h>

#define DELTA_PROGRAM 100000    // How many times the program refreshes
#define RESIZE_PERCENTAGE .90   // What percent full until resizing
#define DELTA_SCAN 0.5          // How many seconds a scan happens
#define DEFAULT_MAX 64          // default max until reallocating is needed
#define DEFAULT_OLD 2592000     // how many days in seconds until a process is old

typedef struct {
    u_int64_t first_seen;
    u_int64_t last_access;      // found in stat(exe) DONE
    u_int64_t last_modified;    // found in stat(exe) DONE
    double cpu_usage;           // stat loc (14, 15)/
    double mem_usage;           // /proc/pid/smaps_rollup Pss
    pid_t pid;                  // stat location 2
    pid_t ppid;                 // stat location 4
    u_int8_t cpu_is_increasing; // cpu_usage math
    u_int8_t mem_is_increasing; // mem_usage math
    char is_running;            // stat location 3
    char is_old;                // DONE
    char *exe_path;             // ???
    char *comm;                 // stat location 1
} proc_data_t;

struct proc_info {
    proc_data_t *data;
    size_t proc_count;
    size_t capacity;
};

#endif // STRUCT_DEF
