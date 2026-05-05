// #include <arpa/inet.h>
// #include <pthread.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>

// #include "../include/proctypes.h"
// #include "../include/logging.h"
// #include "../include/thread.h"
// #include "../include/settings.h"


// notes:
//    commented out for now but plan on resuing this code i think?...probably since im switching to using af_xdp


void get_producer_data(){


}
// void send_packet(struct thread_context_t *context, int type){
//     pthread_mutex_lock(&context->send_data_lock);

//     size_t total_packet_size;
//     // find better way of doing this
//     //
//     //
//     char *packet_buffer;
//     if(type == PROC){
//         total_packet_size = context->p_proc_info->total_ph_size +
//                                    context->p_proc_info->total_tlv_size;
//         char packet_buffer[total_packet_size];
//         memcpy(&packet_buffer, &context->proc_header_buf, context->p_proc_info->total_ph_size);
//         memcpy(
//             &packet_buffer[context->p_proc_info->total_ph_size],
//             &context->proc_data_buf,
//             context->p_proc_info->total_tlv_size
//         );
//     }
//     else if (type == BIN) {
//         total_packet_size = context->p_bin_info->total_ph_size +
//                                    context->p_bin_info->total_tlv_size;
//         char packet_buffer[total_packet_size];
//         memcpy(&packet_buffer, &context->bin_header_buf, context->p_bin_info->total_ph_size);
//         memcpy(
//             &packet_buffer[context->p_bin_info->total_ph_size],
//             &context->bin_data_buf,
//             context->p_bin_info->total_tlv_size
//         );
//     }
//     else if (type == BEAT) {
//         total_packet_size = sizeof(struct packet_header);
//         char packet_buffer[total_packet_size];
//         memcpy(&packet_buffer, &context->beat_header_buf, sizeof(struct packet_header));
//         // no data needed???
//     }
//     else{
//         LOG("wrong type passed in");
//         exit(EXIT_FAILURE);
//     }

//     // split file up to copy data into a ring buffer instead of temp one and then have
//     // the other thread read
//     size_t total_sent = 0;
//     while(total_sent < total_packet_size) {
//         ssize_t sent = send(context->socket_fd, packet_buffer + total_sent,
//                             total_packet_size - total_sent, 0);

//         if(unlikely(sent < 0)){
//             LOG("data was not sent");
//             close(context->socket_fd);
//             exit(EXIT_FAILURE);
//         }

//         total_sent += sent;
//     }

//     close(context->socket_fd);
//     g_finished = 1;
//     pthread_mutex_unlock(&context->send_data_lock);
// }
