#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

typedef struct {
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

    // init these in init_context...??
    struct proc_info *p_proc_info;
    char *header_buf;
    char *data_buf;

} mutext_context_t;

// all functions need a angent context pointer i think

void init_context(mutext_context_t *thread_context);
void destroy_mutexes(mutext_context_t *mutex_context);

#endif // !THREAD_H
