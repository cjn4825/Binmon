#include <stdlib.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/arena.h"
#include "../include/create_buffer.h"
#include "../include/settings.h"
#include "../include/proctypes.h"
#include "../include/protocol.h"
#include "../include/utils.h"
#include "../include/server_connect.h"

sig_atomic_t exit_flag = 0;
int g_finished = 0;

void* create_beat_thread(void *context_arg){
    beat_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    // context->beat_header_buf = create_headerbuf(context->p_beat_info);
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
    // do core pinning here?
    //
    //
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

    // cpu_set_t cpuset;
    // do cpu core pinning here?


    // create arean
    struct Arena *const arena_proc = create_arena();
    alloc_arena(arena_proc, g_proc_pool_size);

    // context->proc_data_buf = create_databuf(context->p_proc_info); // no data buf needed?
    // context->proc_header_buf = create_headerbuf(context->p_proc_info); // header should be added also?

    // put arena for proc and data in context and remove other data
    // don't need data buf i think?
    size_t offset_total = sizeof(struct packet_header) + sizeof(struct proc_data_t);
    size_t offset_to_data = sizeof(struct packet_header);

    while(exit_flag == 0){
        // maybe get rid of proc_info_t? and have the proc pool only have data + flags
        void* proc_data_loc = &arena_proc->pool[arena_proc->offset];
        void* proc_header_loc = &arena_proc->pool[arena_proc->offset];
        scan_procs(proc_data_loc);
        // set header? ...set after data to get size of tlv data?
        // how to transfer data to tlv? memcpy?
        // pack_data(proc_loc);
        // pack_header(proc_loc);                   // these will be in another thread
        // send_packet(proc_loc, PROC);
        // clean(proc_loc, PROC); // don't need to clean anymore?
        //add offset then add proc_loc by that offset
        arena_proc->offset += offset_total;
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
}

void destroy_mutexes(struct thread_context_t *const mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
