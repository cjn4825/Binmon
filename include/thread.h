#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>
#include <signal.h>

struct thread_context_t {
    pthread_mutex_t packet_header_lock;     // lock for building packet header
    pthread_mutex_t pack_lock;              // lock for packing data into tlv
    pthread_mutex_t send_buffer_lock;       // lock for ...
    pthread_mutex_t send_data_lock;
    // pthread_cond_t launch_data;             // condition for threads...
    // size_t capacity;                     // max size of arena... should be in arena struct
    // size_t tail;
    // size_t head;
    // size_t current_size;
    int socket_fd;                          // global file discriptor for the server connection

    struct proc_info_t *p_proc_info;        // global pointer to process information
    struct proc_info_t *p_bin_info;         // global pointer to binary information
    // struct proc_info_t *p_beat_info;        // info for the beat?? think should be removed?
    char *proc_header_buf;                  // determine if these are needed?
    char *bin_header_buf;
    char *beat_header_buf;
    char *proc_data_buf;
    char *bin_data_buf;
};
// volatile tells the compiler that these might change at anytime..
// atomic acts like a lower level way/fast way to mutex the values in a way...
extern volatile sig_atomic_t exit_flag;
extern volatile sig_atomic_t beat_status;
extern volatile sig_atomic_t send_status;
extern volatile sig_atomic_t bin_status;
extern volatile sig_atomic_t proc_status;

void* create_beat_thread(void *context_arg);
void* create_healthbeat_thread(void *context_arg);
void* create_send_thread(void *context_arg);
void* create_bin_thread(void *context_arg);
void* create_proc_thread(void *context_arg);
void init_context(struct thread_context_t *thread_context);
void destroy_mutexes(struct thread_context_t *thread_context);

#endif // !THREAD_H
