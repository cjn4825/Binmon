#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include "../include/thread.h"

// compiler hint macro for unlikely if statement results
#define unlikely(x) __builtin_expect(!!(x), 0)

// macro for handling errors
#define CHECK_ERROR(input, message)                                         \
    do {                                                                    \
       if(input){                                                           \
            LOG(message);                                                   \
            exit(EXIT_FAILURE);                                             \
       }                                                                    \
    } while(0)                                                              \

// create thread in main without having error checking
#define CREATE_THREAD(thread, function)                                     \
    do {                                                                    \
        CHECK_ERROR(pthread_create(&thread, NULL, function, thread_context),\
              "Error when creating thread");                                \
    } while(0)                                                              \

void get_log_time(char *buffer, size_t length);
void check_capacity(struct proc_info_t *p_info);
void clean(struct thread_context_t *context, int type);
void import_settings(const char *path);

#endif // !UTILS_H
