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
};

extern sig_atomic_t exit_flag;
extern sig_atomic_t beat_status;
extern sig_atomic_t send_status;
extern sig_atomic_t bin_status;
extern sig_atomic_t proc_status;

void* create_beat_thread(void *context_arg);
void* create_healthbeat_thread(void *context_arg);
void* create_send_thread(void *context_arg);
void* create_bin_thread(void *context_arg);
void* create_proc_thread(void *context_arg);
void init_context(struct thread_context_t *thread_context);
void destroy_mutexes(struct thread_context_t *thread_context);

#endif // !THREAD_H
