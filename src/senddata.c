#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/logging.h"
#include "../include/thread.h"

void send_packet(struct thread_context_t *context){

    pthread_mutex_lock(&context->send_data_lock);
    // need to detmine how to diff bin for proc...
    size_t total_packet_size = context->p_proc_info->total_ph_size + p_info->total_tlv_size;

    char packet_buffer[total_packet_size];

    // this is wrong since its doing ascii insertion not ints
    memcpy(&packet_buffer, &header_buffer, p_info->total_ph_size);
    memcpy(&packet_buffer[p_info->total_ph_size], &data_buffer, p_info->total_tlv_size);

    size_t total_sent = 0;
    while(total_sent < total_packet_size) {
        ssize_t sent = send(context->socket_fd, packet_buffer + total_sent,
                            total_packet_size - total_sent, 0);

        if(unlikely(sent < 0)){
            LOG("data was not sent");
            close(context->socket_fd);
            exit(EXIT_FAILURE);
        }

        total_sent += sent;
    }

    close(context->socket_fd);
    g_finished = 1;
    pthread_mutex_unlock(&context->send_data_lock);
}
