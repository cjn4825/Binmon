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
    char *header_buf;
    char *data_buf;

};

// not sure if this goes here??? probably not
// also research into what this is exactly
extern volatile sig_atomic_t exit_flag;
// should these return void pointers or just void???
void* create_beat_thread(void *context_arg);
void* create_send_thread(void *context_arg);
void* create_bin_thread(void *context_arg);
void* create_proc_thread(void *context_arg);
void init_context(struct thread_context_t *thread_context);
void destroy_mutexes(struct thread_context_t *thread_context);

#endif // !THREAD_H
