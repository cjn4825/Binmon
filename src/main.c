#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

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

int main(int argc, char *argv[]){
    signal(SIGINT, handle_sigint);

    init_mutexes();

    pthread_t proc_thread;
    pthread_t bin_thread;

    if(argc > 1 && strcmp(argv[1], "-v") == 0){
        g_logging = 1;
        LOG("Agent starting in verbose debug mode...");
    }

    struct proc_info *p_info = create_info();
    struct proc_info *p_bin_info = create_info();

    while(exit_flag == 0){

        // potential race condition ??
        // just make it so once one thread is active then it leaves??
        // g_finished = 0;

        void *packet_data_buffer = create_databuf(p_info);
        void *packet_header_buffer = create_headerbuf(p_info);

        if(unlikely(pthread_create(&proc_thread, NULL, scan_procs(p_info), NULL) != 0)){
            LOG("Failed to create proc_thread");
            exit(EXIT_FAILURE);
        }

        if(unlikely(pthread_create(&bin_thread, NULL, update_bins(p_bin_info), NULL) != 0 )){
            LOG("Failed to create bin_thread");
            exit(EXIT_FAILURE);
        }

        pack_data(p_info, packet_data_buffer);
        pack_header(p_info, packet_header_buffer);
        send_packet(p_info, packet_data_buffer, packet_header_buffer);

        pthread_join(proc_thread, NULL);
        pthread_join(bin_thread, NULL);
        clean(p_info, packet_data_buffer, packet_header_buffer);
        sleep(DELTA_PROGRAM);
    }

    destroy_mutexes();

    return 0;
}
