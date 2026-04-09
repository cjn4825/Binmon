// init threads
// destroy threads
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/thread.h"


void init_context(mutext_context_t *thread_context, int fd){
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

    thread_context->sock_fd = fd;
}

void destroy_mutexes(mutext_context_t *mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
