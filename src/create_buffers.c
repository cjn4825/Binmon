#include <stdlib.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

void* create_info(){

    // using calloc to zeroize the data before hand... i know that once
    // the os give the memory to this it is already all zero's but
    // just for consistancy i'll do this
    struct proc_info_t *p_info = calloc(1, sizeof(struct proc_info_t));

    if(unlikely(p_info == NULL)){
        LOG("Could not calloc proc_info");
        exit(EXIT_FAILURE);
    }

    p_info->capacity = DEFAULT_MAX;

    p_info->data = calloc(p_info->capacity, sizeof(proc_data_t));

    return (void *)p_info;
}

char *create_databuf(struct proc_info_t *p_info){
    char *data_buf = calloc(1, p_info->total_tlv_size);

    if(unlikely(data_buf == NULL)){
        LOG("Could not calloc data_buf");
        exit(EXIT_FAILURE);
    }

    return data_buf;
}

char *create_headerbuf(struct proc_info_t *p_info){
    char *header_buf = calloc(1, p_info->total_ph_size);

    if(unlikely(header_buf == NULL)){
        LOG("Could not calloc header_buf");
        exit(EXIT_FAILURE);
    }

    return header_buf;
}
