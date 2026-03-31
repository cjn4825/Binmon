#include <stdlib.h>
#include <time.h>

#include "../include/proctypes.h"
#include "../include/logging.h"

void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}

void check_capacity(struct proc_info *p_info){
    if(p_info->proc_count >= p_info->capacity * RESIZE_PERCENTAGE){
        size_t new_cap = p_info->capacity *= 2;

        p_info->data = realloc(p_info->data, new_cap);

        if(unlikely(p_info->data == NULL)){
            LOG("Data failed to resize from realloc");
            exit(EXIT_FAILURE);
        }

        // size_t size_remaining = sizeof(proc_data_t) * (new_cap - p_info->proc_count);

        // what is the point of this? i think i wanted to zeroise the newly allocated space
        // but that does not matter
        // memset(&p_info->data[p_info->proc_count], '\0', size_remaining);

        p_info->capacity = new_cap;

    }
}
