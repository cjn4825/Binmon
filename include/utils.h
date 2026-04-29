#ifndef UTILS_H
#define UTILS_H

// compiler hint macro for unlikely if statement results
#include "thread.h"
#define unlikely(x) __builtin_expect(!!(x), 0)

// create thread in main without having error checking
#define CREATE_THREAD(thread, function)                                     \
    do {                                                                    \
        if(pthread_create(&thread, NULL, function, thread_context) != 0) {  \
            LOG("Error when creating thread: ", thread);                    \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while(0)                                                              \

#include <sys/types.h>

void get_log_time(char *buffer, size_t length);
void check_capacity(struct proc_info_t *p_info);
void clean(struct thread_context_t *context, int type);
void import_settings(const char *path);

#endif // !UTILS_H
