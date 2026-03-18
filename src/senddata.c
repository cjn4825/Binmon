#include "../include/proctypes.h"
#include <stdint.h>
#include <string.h>

// these values lets the client know what data each value
// in the data stream is
typedef enum {
    EXE_PATH_T,
    COMM_T,
    FLAGS_T,
    CPU_TABLE_T,
    MEM_TABLE_T,
    LAST_ACCESS_T,
    LAST_MODIFIED_T,
    PID_T,
    PPID_T,
    FIRST_SEEN_T,
    CPU_USAGE_T,
    MEM_USAGE_T,
    START_TIME_T
} data_types;

// need a way to call this function with the index of the data
//
// could use offset by passing in the..well.. offset of the data
static void pack_data(struct proc_info *p_info, uint8_t *network_buffer, int *offset){
    tlv_t t; // this acts like a template that has a fixed size and holds fields for each
    size_t tlv_header_size = sizeof(t.tag) + sizeof(t.length);

    // get working first then could make a function to reduce the lines of code needed?

    t.tag = PID_T;
    t.length = sizeof(uint32_t);
    t.value.u32 = p_info->data->pid;
    memcpy(network_buffer + *offset, &t, tlv_header_size);
    *offset += tlv_header_size;

    t.tag = PPID_T;
    t.length = sizeof(uint32_t);
    t.value.u32 = p_info->data->ppid;
    memcpy(network_buffer + *offset, &t, tlv_header_size);
    *offset += tlv_header_size;

    // continue for other types
}
