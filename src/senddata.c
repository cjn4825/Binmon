#include "../include/proctypes.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// static uint32_t checksum(struct proc_info *p_info){
//     uint32_t checksum = 0;
//     for(size_t i = 0; i < p_info->proc_count; i++){
//         checksum +=
//     }
//     return checksum;
// }

// use htonl for every field individually only if they are greater than
// one byte since the value does not change

void send_data(struct proc_info *p_info, char *network_buffer){
    // create packet header
    // make sure its the one in network_buffer
    uint32_t header_size = sizeof(struct packet_header);
    size_t total_packet_size = header_size + p_info->tlv_size;

    struct packet_header header = {
        .magic_number = htonl((uint32_t)MAGIC_NUMBER),
        .payload_length = htonl(total_packet_size),
        .version = htonl(1.0),
        .sequence = htonl(p_info->sequence++),
        // .crc = htonl(0)
    };

    memcpy(network_buffer, &header, sizeof(header));

    struct sockaddr_in server_address;

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(sock_fd < 0){
        // log error message
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

    if(connect(sock_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0){
        // log error message
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    size_t total_sent = 0;
    while(total_sent < total_packet_size) {
        ssize_t sent = send(sock_fd, network_buffer + total_sent,
                            total_packet_size - total_sent, 0);

        if(sent < 0){
            // log error message
            close(sock_fd);
            exit(EXIT_FAILURE);
        }

        total_sent += sent;
    }

    close(sock_fd);
}
