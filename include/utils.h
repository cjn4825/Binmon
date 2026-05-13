#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include "../include/thread.h"

// compiler hint macro for unlikely if statement results
#define unlikely(x) __builtin_expect(!!(x), 0)

// for figuring out the type of element in yaml parsing
#define STATE_NONE 0
#define STATE_KEY 1
#define STATE_VALUE 2

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
void import_settings(const char *path);

#endif // !UTILS_H
