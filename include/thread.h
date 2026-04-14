#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>
#include <signal.h>

struct thread_context_t {
    pthread_mutex_t packet_header_lock;
    pthread_mutex_t pack_lock;
    pthread_mutex_t send_buffer_lock;
    pthread_mutex_t send_data_lock;
    pthread_cond_t launch_data;
    size_t capacity;
    size_t tail;
    size_t head;
    size_t current_size;
    int socket_fd;

    struct proc_info_t *p_proc_info;
    struct proc_info_t *p_bin_info;
    char *proc_header_buf;
    char *proc_data_buf;
    char *bin_header_buf;
    char *bin_data_buf;

};

// notes: atomic means all the steps with the variable
// have to happen...like x++ is 3 operations for example
// volitile means the the variable will not be cached...so other threads
// are guaranteed to read it correctly???
extern volatile sig_atomic_t exit_flag;
// need to define these somewhere also make sure this is correct...
extern volatile sig_atomic_t beat_status;
extern volatile sig_atomic_t health_status;
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
