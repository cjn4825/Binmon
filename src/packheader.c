#include <arpa/inet.h>
#include <stdint.h>

#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/thread.h"
#include "../include/settings.h"

// checksum will sum all the amount of tlv data in the packet for now???
// could just multiply but ... idk
// static uint32_t checksum(struct proc_info_t *p_info){
//     uint32_t checksum = 0;
//     for(size_t i = 0; i < p_info->proc_count; i++){
//         checksum += sizeof(struct tlv_t);
//     }
//     return checksum;
// }

void pack_header(struct thread_context_t *context, void *proc_header_loc){

    struct packet_header *ph = (struct packet_header*)proc_header_loc;
    ph->magic_number = htonl((uint32_t)MAGIC_NUMBER);
    ph->payload_length = htonl(sizeof(struct packet_header)
            // need to get exact size of this...update value in context?
            + sizeof(struct tlv_t));
    ph->version = htonl(VERSION);
    ph->sequence = htonl(context->p_proc_info->sequence++);// change to combine bin and proc
    ph->crc = htonl(0); // for now...fix checksum

}
