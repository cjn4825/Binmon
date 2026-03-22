#ifndef UTILS_H
#define UTILS_H

// compiler hint macro for unlikely if statement results
#define unlikely(x) __builtin_expect(!!(x), 0)

#include <sys/types.h>

void get_log_time(char *buffer, size_t length);

#endif // UTILS_H
