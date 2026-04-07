
#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

extern pthread_mutex_t packet_header_lock;
extern pthread_mutex_t pack_lock;
extern pthread_mutex_t send_lock;

void init_mutexes(void);
void destroy_mutexes(void);

#endif // !THREAD_H
