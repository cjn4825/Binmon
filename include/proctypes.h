#ifndef STRUCT_DEF
#define STRUCT_DEF

#include <sys/types.h>
#include <stdbool.h>

#define DELTA_PROGRAM 100000    // How many times the program refreshes
#define RESIZE_PERCENTAGE .90   // What percent full until resizing
#define DELTA_SCAN 0.5          // How many seconds a scan happens
#define DEFAULT_MAX 64          // default max until reallocating is needed
#define DEFAULT_OLD 2592000     // how many days in seconds until a process is old(30 days)

typedef struct {
    u_int64_t last_access;
    u_int64_t last_modified;
    double first_seen;          // first seen time thats persistant
    double cpu_usage;
    double mem_usage;           // /proc/pid/smaps_rollup Pss
    double start_time;
    pid_t pid;
    pid_t ppid;
    u_int8_t cpu_up;
    u_int8_t mem_up;
    u_int8_t is_old;
    u_int8_t previous_ran;
    u_int8_t state;
    const char *exe_path;
    const char *comm;
} proc_data_t;

struct proc_info {
    proc_data_t *data;
    size_t proc_count;
    size_t capacity;
};

#endif // STRUCT_DEF
