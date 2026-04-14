#include <stdlib.h>
#include <time.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}

//
//research better way to do this... maybe just a simple
//number pass in that tells what type of cleaning to do
void clean_proc(struct thread_context_t *context){
    free(context->p_proc_info->data);
    free(context->header_buf);
    context->p_proc_info->total_tlv_size = 0;
    context->p_proc_info->total_ph_size = 0;
}

void clean_bin(struct thread_context_t *context){
    free(context->p_bin_info->data);
    free(context->header_buf);
    context->p_bin_info->total_tlv_size = 0;
    context->p_bin_info->total_ph_size = 0;
}

void check_capacity(struct proc_info_t *p_info){
    if(p_info->proc_count >= p_info->capacity * RESIZE_PERCENTAGE){
        size_t new_cap = p_info->capacity *= 2;

        p_info->data = realloc(p_info->data, new_cap);

        if(unlikely(p_info->data == NULL)){
            LOG("Data failed to resize from realloc");
            exit(EXIT_FAILURE);
        }

        p_info->capacity = new_cap;

    }
}
