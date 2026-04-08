
#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

typedef struct {
    pthread_mutex_t packet_header_lock;
    pthread_mutex_t pack_lock;
    pthread_mutex_t send_lock;

} mutext_context_t;

void init_mutexes(mutext_context_t *mutex_context);
void destroy_mutexes(mutext_context_t *mutex_context);

#endif // !THREAD_H
