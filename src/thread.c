// init threads
// destroy threads
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/thread.h"

pthread_mutex_t packet_header_lock;
pthread_mutex_t pack_lock;
pthread_mutex_t send_lock;

void init_mutexes(void){
    if(unlikely(pthread_mutex_init(&packet_header_lock, NULL) != 0)){
        LOG("Failed to create packet_header_lock mutex");
        exit(EXIT_FAILURE);
    }

    if(unlikely(pthread_mutex_init(&pack_lock, NULL) != 0)){
        LOG("Failed to create pack_lock mutex");
        exit(EXIT_FAILURE);
    }

    if(unlikely(pthread_mutex_init(&send_lock, NULL) != 0)){
        LOG("Failed to create send_lock mutex");
        exit(EXIT_FAILURE);
    }
}

void destroy_mutexes(void){
    pthread_mutex_destroy(&packet_header_lock);
    pthread_mutex_destroy(&pack_lock);
    pthread_mutex_destroy(&send_lock);
}
