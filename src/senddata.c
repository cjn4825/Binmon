#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/logging.h"


// use htonl for every field individually only if they are greater than
// one byte since the value does not change

void send_packet(struct proc_info *p_info, char *data_buffer, char *header_buffer){

    size_t total_packet_size = p_info->total_ph_size + p_info->total_tlv_size;

    char packet_buffer[total_packet_size];

    memcpy(&packet_buffer, &header_buffer, p_info->total_ph_size);
    memcpy(&packet_buffer[p_info->total_ph_size], &data_buffer, p_info->total_tlv_size);

    struct sockaddr_in server_address;

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(unlikely(sock_fd < 0)){
        LOG("socket could not be created");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

    if(unlikely(connect(sock_fd, (struct sockaddr *)&server_address,
       sizeof(server_address)) < 0)){

        LOG("failed to set connection for socket");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    size_t total_sent = 0;
    while(total_sent < total_packet_size) {
        ssize_t sent = send(sock_fd, packet_buffer + total_sent,
                            total_packet_size - total_sent, 0);

        if(unlikely(sent < 0)){
            LOG("data was not sent");
            close(sock_fd);
            exit(EXIT_FAILURE);
        }

        total_sent += sent;
    }

    close(sock_fd);
    g_finished = 1;
}
