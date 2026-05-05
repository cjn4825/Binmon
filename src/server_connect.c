#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/settings.h"

int server_connect(void){
    struct sockaddr_in server_address;

    int connected;
    int backoff = 1;
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    CHECK_ERROR(unlikely(sock_fd < 0), "socket could not be created");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(config->g_port);
    server_address.sin_addr.s_addr = inet_addr(config->g_server_address);

    while(backoff <= (backoff * 5)){
        if(connect(sock_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0){
            LOG("failed to set connection for socket trying again...");
        }
        else{
            LOG("connected to server!");
            connected = 0;
            break;
        }

        sleep(backoff);
        backoff *= 2;
    }
    if(connected == 1){
        LOG("failed to set connection for socket");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    return sock_fd;
}
