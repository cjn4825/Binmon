#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>

#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/settings.h"

// these values lets the client know what data each value
// in the data stream is
typedef enum {
    EXE_PATH,
    COMM,
    LAST_ACCESS,
    LAST_MODIFIED,
    LAST_STATUS,
    PID,
    PPID,
    FIRST_SEEN,
    CPU_USAGE,
    MEM_USAGE,
    START_TIME,
    FILE_SIZE,
    FLAGS
} data_types;

//TODO; change to use loop instead since this is very wasteful of space
/*
 *  somehow loop through enum and set type depending on enum value?
 *  with that i can set all other values for the most part...
 *
 */

void pack_data(void* start_offset, int num_elements){

    // no need to pack data???
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    //
    // notes: this is called per process so 14 or so fields in total
    // implement just for proc data for now?
    for(int i = 0; i < num_elements; i++){

        // the struct of data will be set at the location needed
        // could manually loop by type? such as i know 3 u32 ints are first so loop by that amount then continue
        start_offset[tlv_offset] = //somehow get type by index;
    }
























    for(size_t i = 0; i < context->p_proc_info->proc_count; i++){
        t.tag = EXE_PATH;
        strcpy(t.value.string, context->p_proc_info->data[i].exe_path);
        t.length = strlen(t.value.string);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(context->p_proc_info->data[i].exe_path);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("Exe_path set");

        t.tag = COMM;
        strcpy(t.value.string, context->p_proc_info->data[i].comm);       // segfault issue with comm
        t.length = strlen(t.value.string);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(context->p_proc_info->data[i].comm);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("comm set");

        t.tag = LAST_ACCESS;
        t.length = htonl(sizeof(t.value.u32));
        t.value.u32 = htonl(context->p_proc_info->data[i].last_access);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u32);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("last_access set");

        t.tag = LAST_MODIFIED;
        t.length = htonl(sizeof(t.value.u32));
        t.value.u32 = htonl(context->p_proc_info->data[i].last_modified);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u32);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("last_modified set");

        t.tag = LAST_STATUS;
        t.length = htonl(sizeof(t.value.u32));
        t.value.u32 = htonl(context->p_proc_info->data[i].last_status);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u32);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("last_access set");

        t.tag = PID;
        t.length = htonl(sizeof(t.value.u32));
        t.value.u32 = htonl(context->p_proc_info->data[i].pid);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u32);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("pid set");

        t.tag = PPID;
        t.length = htonl(sizeof(t.value.u32));
        t.value.u32 = htonl(context->p_proc_info->data[i].ppid);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u32);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("ppid set");

        t.tag = FIRST_SEEN;
        t.length = htons(sizeof(t.value.u16));
        t.value.u16 = htons(context->p_proc_info->data[i].first_seen);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u16);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("first_seen set");

        t.tag = CPU_USAGE;
        t.length = htons(sizeof(t.value.u16));
        t.value.u16 = htons(context->p_proc_info->data[i].cpu_usage);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u16);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("cpu_usage set");

        t.tag = MEM_USAGE;
        t.length = htons(sizeof(t.value.u16));
        t.value.u16 = htons(context->p_proc_info->data[i].mem_usage);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u16);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("mem_usage set");

        t.tag = START_TIME;
        t.length = htons(sizeof(t.value.u16));
        t.value.u16 = htons(context->p_proc_info->data[i].start_time);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u16);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("start_time set");

        t.tag = FILE_SIZE;
        t.length = htons(sizeof(t.value.u16));
        t.value.u16 = htons(context->p_proc_info->data[i].file_size);
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u16);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("file_size set");

        t.tag = FLAGS;
        t.length = sizeof(t.value.u8);
        // include more inside of bitfield
        uint8_t temp_state = context->p_proc_info->data[i].flags_table.state;
        t.value.u8 = temp_state;
        tlv_size = sizeof(t.tag) + sizeof(t.length) + sizeof(t.value.u8);
        memcpy(offset, &t, tlv_size);
        total_tlv_size += tlv_size;
        offset += tlv_size;
        LOG("flags set");

        // this might be a little faster since i keep adding within here
        // until the end instead of multiple times
        context->p_proc_info->total_tlv_size = total_tlv_size;
    }
}
