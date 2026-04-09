#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"
// #include "../include/thread_create.h"

int g_logging = 0;
int g_finished = 0;

//
// not sure if this goes here or in the headerfile
// find best way to do this...
volatile sig_atomic_t exit_flag = 0;

static void* create_info(){

    // using calloc to zeroize the data before hand... i know that once
    // the os give the memory to this it is already all zero's but
    // just for consistancy i'll do this
    struct proc_info *p_info = calloc(1, sizeof(struct proc_info));

    if(unlikely(p_info == NULL)){
        LOG("Could not calloc proc_info");
        exit(EXIT_FAILURE);
    }

    p_info->capacity = DEFAULT_MAX;

    p_info->data = calloc(p_info->capacity, sizeof(proc_data_t));

    return (void *)p_info;
}

static char *create_databuf(struct proc_info *p_info){
    char *data_buf = calloc(1, p_info->total_tlv_size);

    if(unlikely(data_buf == NULL)){
        LOG("Could not calloc data_buf");
        exit(EXIT_FAILURE);
    }

    return data_buf;
}

// put in another file and make sure to remove network include
static char *create_headerbuf(struct proc_info *p_info){
    char *header_buf = calloc(1, p_info->total_ph_size);

    if(unlikely(header_buf == NULL)){
        LOG("Could not calloc header_buf");
        exit(EXIT_FAILURE);
    }

    return header_buf;
}

static inline void clean(struct proc_info *p_info, char *data_buf, char *ph_buf){
    free(data_buf);
    free(ph_buf);
    p_info->total_tlv_size = 0;
    p_info->total_ph_size = 0;
}


int server_connect(void){
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

static void* create_beat_thread(void *p_info){

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

static void* create_send_thread(void *p_info){

    // this will read the shared queue buffer
    // and use values from the tlv packets and
    // index updates to send data
    // then it will free the data and adjust the
    // index

    return NULL;
}

// static void create_thread(pthread_t thread, struct proc_info *p, thread_func_t func){
static void* create_bin_thread(void *p_bin){

    struct proc_info *p_bin_info = create_info();

    while(exit_flag == 0){

        // pack_data(p_info, packet_data_buffer);
        // pack_header(p_info, packet_header_buffer);
        // send_packet(p_info, packet_data_buffer, packet_header_buffer);

        // clean(p_info, packet_data_buffer, packet_header_buffer);
        sleep(BIN_SCAN_TIME);
    }


    // if(unlikely(pthread_create(&bin_thread, NULL, update_bins(d), NULL) != 0 )){
    //     LOG("Failed to create bin_thread");
    //     exit(EXIT_FAILURE);
    // }
    //

    return NULL;
}

static void* create_proc_thread(void *p_proc){

    struct proc_info *p_info = create_info();

    while(exit_flag == 0){
        scan_procs(p_proc);

        // pack_data(p_info, packet_data_buffer);
        // pack_header(p_info, packet_header_buffer);
        // send_packet(p_info, packet_data_buffer, packet_header_buffer);

        // clean(p_info, packet_data_buffer, packet_header_buffer);
        sleep(DELTA_PROGRAM);
    }

    return NULL;
}

//
//
//put in own file

int main(int argc, char *argv[]){
    signal(SIGINT, handle_sigint);

    if(argc > 1 && strcmp(argv[1], "-v") == 0){
        g_logging = 1;
        LOG("Agent starting in verbose debug mode...");
    }

    mutext_context_t *mutex_context = calloc(3, sizeof(pthread_mutex_t));
    init_context(mutex_context, server_connect());

    pthread_t proc_thread;
    pthread_t bin_thread;
    pthread_t send_data_thread;
    pthread_t heart_beat_thread;

    // potential race condition ??
    // just make it so once one thread is active then it leaves??
    // g_finished = 0;

    //
    //
    // create pointer field in manager struct to point to both header and data buffers
    // void *packet_data_buffer = create_databuf(p_info);
    // void *packet_header_buffer = create_headerbuf(p_info);

    pthread_create(&bin_thread, NULL, create_proc_thread, mutex_context);
    pthread_create(&proc_thread, NULL, create_bin_thread, mutex_context);
    pthread_create(&send_data_thread, NULL, create_send_thread, mutex_context);
    pthread_create(&heart_beat_thread, NULL, create_beat_thread, mutex_context);

    pthread_join(proc_thread, NULL);
    pthread_join(bin_thread, NULL);

    destroy_mutexes(mutex_context);
    free(mutex_context);

    return 0;
}
