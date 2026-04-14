#ifndef UTILS_H
#define UTILS_H

// compiler hint macro for unlikely if statement results
#include "thread.h"
#define unlikely(x) __builtin_expect(!!(x), 0)

#include <sys/types.h>

void get_log_time(char *buffer, size_t length);
void check_capacity(struct proc_info_t *p_info);
void clean_proc(struct thread_context_t *context);
void clean_bin(struct thread_context_t *context);

#endif // !UTILS_H
