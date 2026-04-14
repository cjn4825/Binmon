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
int g_finished = 0; // with multithreading this wont work...

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

void* create_beat_thread(void *context_arg){
    // wasn't typedef struct not avaliable between multiple files or something???
    //
    //
    struct thread_context_t *context = (struct thread_context_t *)context_arg;
    while(exit_flag == 0){
        usleep(DELTA_PROGRAM);
    }

    // sleep until a signal is sent to this thread
    // then it will send a "beat" to the server
    //
    // create another file to handle all of this
    // as i would need to construct a packet too
    // do it with the main thread and just have
    // a pointer to it
    // then just add to buffer

    return NULL;
}

void* create_send_thread(void *context_arg){
    // wasn't typedef struct not avaliable between multiple files or something???
    //
    //
    struct thread_context_t *context = (struct thread_context_t *)context_arg;

    while(exit_flag == 0){
        usleep(DELTA_PROGRAM);
    }
    // this will read the shared queue buffer
    // and use values from the tlv packets and
    // index updates to send data
    // then it will free the data and adjust the
    // index

    return NULL;
}

void* create_bin_thread(void *context_arg){

    // void *packet_data_buffer = create_databuf(p_info);
    // void *packet_header_buffer = create_headerbuf(p_info);
    //
    //
    struct thread_context_t *context = (struct thread_context_t *)context_arg;

    struct proc_info_t *p_bin_info = create_info();
    context->p_bin_info = p_bin_info;

    while(exit_flag == 0){

        pack_data(context);
        pack_header(context);
        send_packet(context);
        clean_bin(context);

        sleep(BIN_SCAN_TIME);
    }

    return NULL;
}

void* create_proc_thread(void *context_arg){
    struct thread_context_t *context = (struct thread_context_t *)context_arg;
    context->p_proc_info = create_info();

    // research into how i could share these between proc and bin
    // probably just make it two seperate ones for now...don't know if the header
    // is the same could put that in the thread_context struct
    void *packet_data_buffer = create_databuf(context->p_proc_info);
    void *packet_header_buffer = create_headerbuf(context->p_proc_info);

    while(exit_flag == 0){
        scan_procs(context->p_proc_info);

        pack_data(context);
        pack_header(context);
        send_packet(context);

        clean_proc(context);
        sleep(DELTA_PROGRAM);
    }

    return NULL;
}

void init_context(struct thread_context_t *thread_context){

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
}

void destroy_mutexes(struct thread_context_t *mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
