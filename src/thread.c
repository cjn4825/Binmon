#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/create_buffer.h"
#include "../include/settings.h"
#include "../include/proctypes.h"
#include "../include/utils.h"

volatile sig_atomic_t exit_flag = 0;
int g_finished = 0;

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
    server_address.sin_port = htons(g_port);
    server_address.sin_addr.s_addr = inet_addr(g_server_address);

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

void* create_beat_thread(void *context_arg){
    beat_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    context->beat_header_buf = create_headerbuf(context->p_beat_info);
    // decide what info to init inside the header
    //
    //
    while(exit_flag == 0){
        sleep(g_beat_scan_time);
        send_packet(context, BEAT);
    }

    return NULL;
}

void* create_healthbeat_thread(void *context_arg){
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    while(exit_flag == 0){
        if(beat_status) LOG("beat signal lost");
        if(send_status) LOG("send signal lost");
        if(bin_status) LOG("bin signal lost");
        if(proc_status) LOG("proc signal lost");
        sleep(g_health_scan_time);
    }
    return NULL;
}

void* create_send_thread(void *context_arg){
    send_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    while(exit_flag == 0){
        usleep(g_delta_program);
    }
    // this will read the shared queue buffer
    // and use values from the tlv packets and
    // index updates to send data
    // then it will free the data and adjust the
    // index

    return NULL;
}

void* create_bin_thread(void *context_arg){
    bin_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    context->p_bin_info = create_info();

    context->bin_data_buf = create_databuf(context->p_bin_info);
    context->bin_header_buf = create_headerbuf(context->p_bin_info);

    while(exit_flag == 0){
        update_bins(context);
        pack_data(context);
        pack_header(context);
        send_packet(context, BIN);
        clean(context, BIN);

        sleep(g_bin_scan_time);
    }

    return NULL;
}

void* create_proc_thread(void *context_arg){
    proc_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    context->p_proc_info = create_info();

    context->proc_data_buf = create_databuf(context->p_proc_info);
    context->proc_header_buf = create_headerbuf(context->p_proc_info);

    while(exit_flag == 0){
        scan_procs(context);
        pack_data(context);
        pack_header(context);
        send_packet(context, PROC);
        clean(context, PROC);

        sleep(g_delta_program);
    }

    return NULL;
}

void init_context(struct thread_context_t *const thread_context){

    int fd = server_connect();

    // not sure if i should use unlikely here???
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
    // create shared pool
}

void destroy_mutexes(struct thread_context_t *const mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
