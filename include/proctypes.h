#ifndef STRUCT_DEF
#define STRUCT_DEF

#include <sys/types.h>
#include <stdbool.h>

#define DELTA_PROGRAM 100000    // How many times the program refreshes
#define RESIZE_PERCENTAGE .90   // What percent full until resizing
#define DELTA_SCAN 0.5          // How many seconds a scan happens
#define DEFAULT_MAX 64          // default max until reallocating is needed
#define DEFAULT_OLD 2592000     // how many days in seconds until a process is old(30 days)


// packet structure for
// sending over the
// internet
struct packet {
    //
} __attribute__((packed));

// to save space i could just factor
// in the whole number values
typedef struct {
    double cpu_usage_1;
    double cpu_usage_2;
    double cpu_usage_3;
    double cpu_usage_4;
    double cpu_usage_5;
} proc_cpu_usage_t;

typedef struct {
    double mem_usage_1;
    double mem_usage_2;
    double mem_usage_3;
    double mem_usage_4;
    double mem_usage_5;
} proc_mem_usage_t;

typedef struct {
    u_int64_t last_access;
    u_int64_t last_modified;
    double first_seen;          // first seen time thats persistant
    double cpu_usage;
    double mem_usage;
    double start_time;          // time if process started in current session
    pid_t pid;
    pid_t ppid;
    u_int8_t cpu_up;
    u_int8_t mem_up;
    u_int8_t is_old;
    u_int8_t previous_ran;
    u_int8_t state;
    char *exe_path;             // when should i be using const char? put in notes
    proc_cpu_usage_t *cpu_table;
    proc_mem_usage_t *mem_table;
    const char *comm;
} proc_data_t;

struct proc_info {
    proc_data_t *data;
    size_t proc_count;
    size_t capacity;
};

void update_capacity(struct proc_info *p_info);
void save_state(struct proc_info *p_info);
void scan_procs(struct proc_info *p_info);
void load_state(struct proc_info *p_info);

#endif // STRUCT_DEF
