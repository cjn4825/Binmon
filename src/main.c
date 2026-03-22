#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/protocol.h"

struct proc_info* global_struct_ptr = NULL;
volatile sig_atomic_t exit_flag = 0;

int g_logging = 0;

static void handle_sigint(int sig){
    if (global_struct_ptr != NULL) {
        exit_flag = 1;

        // goal is to send the data out fully then it can exit?
        global_struct_ptr = NULL; // fix later
        exit(0);
    }
}

static struct proc_info* create_info(){

    // using calloc to zeroize the data before hand... i know that once
    // the os give the memory to this it is already all zero's but
    // just for consistancy i'll do this
    struct proc_info *p_info = calloc(1, sizeof(struct proc_info));

    if(!p_info){
        LOG("Could not calloc proc_info");
        exit(EXIT_FAILURE);
    }

    p_info->capacity = DEFAULT_MAX;

    p_info->data = calloc(p_info->capacity, sizeof(proc_data_t));

    // adjust for additional information added in headerfile

    return p_info;
}

static char *create_netbuf(struct proc_info *p_info){
    size_t header_size = sizeof(struct packet_header);
    size_t data_size = p_info->proc_count * sizeof(tlv_t);
    char *net_buf = calloc(1, header_size + data_size);

    return net_buf;
}

static inline void clean(struct proc_info *p_info, char *network_buffer){
    free(network_buffer);
    p_info->tlv_size = 0;
}

int main(int argc, char *argv[]){

    if(argc > 1 && strcmp(argv[1], "-v") == 0){
        g_logging = 1;
        LOG("Agent starting in verbose debug mode...");
    }

    struct proc_info *p_info = create_info();

    global_struct_ptr = p_info;
    signal(SIGINT, handle_sigint);

    while(exit_flag == 0) {

        scan_data(p_info);
        char *network_buffer = create_netbuf(p_info);
        pack_data(p_info, network_buffer);
        send_data(p_info, network_buffer);

        // only things that are reused everytime that is heap allocated
        // need to be freed within the clean function...so make sure to find those
        clean(p_info, network_buffer);
        sleep(DELTA_PROGRAM);
    }

    return 0;
}
