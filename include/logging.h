#ifndef LOG

#include <stdio.h>

#include "../include/utils.h"

#define LOG(message, ...)                                                                \
    do {                                                                                 \
        if(g_log_value == 1) {                                                           \
            char time_buffer[10];                                                        \
            get_log_time(time_buffer, sizeof(time_buffer));                              \
            fprintf(stderr, "[%s][DEBUG] %s:%d | ", time_buffer, __FILE__, __LINE__);    \
            fprintf(stderr, (message), ##__VA_ARGS__);                                   \
            fprintf(stderr, "\n");                                                       \
        }                                                                                \
    }  while(0)

void set_logging(void);

#endif // !LOG
