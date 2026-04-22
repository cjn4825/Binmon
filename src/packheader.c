#include <arpa/inet.h>
#include <stdint.h>

#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/thread.h"
#include "../include/settings.h"

// checksum will sum all the amount of tlv data in the packet for now???
// could just multiply but ... idk
static uint32_t checksum(struct proc_info_t *p_info){
    uint32_t checksum = 0;
    for(size_t i = 0; i < p_info->proc_count; i++){
        checksum += sizeof(struct tlv_t);
    }
    return checksum;
}

void pack_header(struct thread_context_t *context){
    pthread_mutex_lock(&context->packet_header_lock);

    struct packet_header header = {
        .magic_number = htonl((uint32_t)MAGIC_NUMBER),
        .payload_length = htonl(sizeof(struct packet_header)),
        .version = htonl(VERSION),
        .sequence = htonl(context->p_proc_info->sequence++),
        .crc = htonl(checksum(context->p_proc_info))
    };

    context->p_proc_info->total_ph_size = sizeof(header);
    pthread_mutex_unlock(&context->packet_header_lock);
}
