#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/arena.h"
#include "../include/create_headers.h"
#include "../include/settings.h"
#include "../include/proctypes.h"
#include "../include/utils.h"
#include "../include/server_connect.h"

void* create_beat_thread(void *context_arg){
    beat_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    // context->beat_header_buf = create_headerbuf(context->p_beat_info);
    // decide what info to init inside the header
    //
    //
    while(exit_flag == 0){
        sleep(config->g_beat_scan_time);
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
        sleep(config->g_health_scan_time);
    }
    return NULL;
}

void* create_send_thread(void *context_arg){
    send_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    while(exit_flag == 0){
        usleep(config->g_delta_program);
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
    // context->p_bin_info = create_info();

    // context->bin_data_buf = create_databuf(context->p_bin_info);
    // context->bin_header_buf = create_headerbuf(context->p_bin_info);

    while(exit_flag == 0){
        // update_bins(context);
        // pack_data(context);
        // pack_header(context);
        // send_packet(context, BIN);
        // clean(context, BIN);

        sleep(config->g_bin_scan_time);
    }

    return NULL;
}
// goal is to add proces values as fast as possible to the pool
void* create_proc_thread(void *context_arg){
    proc_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    // cpu_set_t cpuset;
    // do cpu core pinning here?

    struct Arena *const arena_proc = create_arena();
    alloc_arena(arena_proc, config->g_proc_pool_size);


    void* p_offset = create_headers(&arena_proc->pool[0]);

    size_t start_loc = (size_t)((uintptr_t)arena_proc->pool + (uintptr_t)p_offset);
    arena_proc->offset = start_loc;

    size_t header_offset = sizeof(struct packet_header);
    size_t next_proc_offset = header_offset + sizeof(struct proc_data_t);

    while(exit_flag == 0){
        void* proc_data_loc = &arena_proc->pool[arena_proc->offset + header_offset];

        scan_procs(proc_data_loc);
        // make sure to make space for the binmon header before


        create_binmon_header(&arena_proc->offset - header_offset);


        arena_proc->offset += next_proc_offset;

        //
        // sig atomic???
        //
        // this returns the previoud value after adding the offset to it?
        // void* proc_block = atomic_fetch_add(proc_header_loc, offset_total);
        // this block pointer then gets pushed to the ring buffer

        sleep(config->g_delta_program);
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
