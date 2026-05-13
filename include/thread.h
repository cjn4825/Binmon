#ifndef THREAD_H
#define THREAD_H

#include <signal.h>

#include "../include/send_data.h"

struct thread_context_t {
    struct send_queue *queue_proc;
    struct send_queue *queue_bin;
    uint8_t *pool_proc;
    uint8_t *pool_bin;
    int socket_fd;                          // global file discriptor for the server connection
};

extern volatile sig_atomic_t exit_flag;
extern _Atomic int beat_status;
extern _Atomic int send_status;
extern _Atomic int bin_status;
extern _Atomic int proc_status;

void* create_beat_thread(void *context_arg);
void* create_healthbeat_thread(void *context_arg);
void* create_send_thread(void *context_arg);
void* create_bin_thread(void *context_arg);
void* create_proc_thread(void *context_arg);
void init_context(struct thread_context_t *thread_context);

#endif // !THREAD_H
