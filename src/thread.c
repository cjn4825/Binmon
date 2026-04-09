// init threads
// destroy threads
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/thread.h"

static int server_connect(void){
    struct sockaddr_in server_address;

    int connected;
    int backoff = 1;
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(unlikely(sock_fd < 0)){
        LOG("socket could not be created");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

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

void init_context(mutext_context_t *thread_context){

    int fd = server_connect();

    if(unlikely(pthread_mutex_init(&thread_context->packet_header_lock, NULL) != 0)){
        LOG("Failed to create packet_header_lock mutex");
        exit(EXIT_FAILURE);
    }

    if(unlikely(pthread_mutex_init(&thread_context->pack_lock, NULL) != 0)){
        LOG("Failed to create pack_lock mutex");
        exit(EXIT_FAILURE);
    }

    if(unlikely(pthread_mutex_init(&thread_context->send_buffer_lock, NULL) != 0)){
        LOG("Failed to create send_buffer_lock mutex");
        exit(EXIT_FAILURE);
    }

    if(unlikely(pthread_mutex_init(&thread_context->send_data_lock, NULL) != 0)){
        LOG("Failed to create send_data_lock mutex");
        exit(EXIT_FAILURE);
    }

    thread_context->socket_fd = fd;
}

void destroy_mutexes(mutext_context_t *mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
