#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
// #include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/arena.h"
#include "../include/create_headers.h"
#include "../include/settings.h"
#include "../include/proctypes.h"
#include "../include/bintypes.h"
#include "../include/utils.h"
#include "../include/send_data.h"
#include "../include/server_connect.h"

void pin_thread(int core, pthread_t thread){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    if(pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0){
        LOG("error setting pinning affinity");
        exit(EXIT_FAILURE);
    }
}

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

void* create_bin_thread(void *context_arg){
    // could put in yaml file?
    pin_thread(1, pthread_self());

    bin_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    struct Arena *const arena_bin = create_arena();
    arena_bin->capacity = sizeof(arena_bin->pool);
    arena_bin->pool = alloc_arena(arena_bin, config->g_bin_pool_size);

    void* start_loc = create_headers(&arena_bin->pool);

    arena_bin->offset = sizeof(start_loc);

    size_t header_offset = sizeof(struct packet_header);

    while(exit_flag == 0){
        void* bin_data_loc = &arena_bin->pool[arena_bin->offset + header_offset];
        scan_bins(bin_data_loc); // fix to just take in base pointer
        create_binmon_header(&arena_bin->offset - header_offset); // see if right?

        // push pointer to end of consumer pool

        sleep(config->g_bin_scan_time);
    }

    return NULL;
}
// goal is to add proces values as fast as possible to the pool
void* create_proc_thread(void *context_arg){
    pin_thread(2, pthread_self());
    proc_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    struct Arena *const arena_proc = create_arena();
    arena_proc->capacity = sizeof(arena_proc->pool);
    arena_proc->pool = alloc_arena(arena_proc, config->g_proc_pool_size);

    void* start_loc = create_headers(&arena_proc->pool);

    arena_proc->offset = sizeof(start_loc);

    size_t header_offset = sizeof(struct packet_header);
    size_t next_proc_offset = header_offset + sizeof(struct proc_data_t);

    while(exit_flag == 0){
        void* proc_data_loc = &arena_proc->pool[arena_proc->offset + header_offset];

        scan_procs(proc_data_loc);

        create_binmon_header(&arena_proc->offset - header_offset);
        // adjust total size atomic value in main header...then just reset it
        // once done

        // push pointer to end of consumer pool
        arena_proc->offset += next_proc_offset;


        //
        // sig atomic???
        //

        sleep(config->g_delta_program);
    }

    return NULL;
}

// used as the consumer thread
void* create_send_thread(void *context_arg){
    pin_thread(3, pthread_self());
    send_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    struct Arena *const arena_send = create_arena();
    arena_send->capacity = sizeof(arena_send->pool);
    arena_send->pool = alloc_arena(arena_send, config->g_send_pool_size);
    arena_send->offset = arena_send->pool;
    while(exit_flag == 0){
        // have condition set that gets pushed when data is in both producers
        // pointers get pushed from producers and put in this queue...
        // then calls af_xdp or whatever to then push the packet

        // how to determine the type???
        void* data = get_producer_data();

        // function that tell af_xdp to send the data
        // then move offset pointer only if not less then base pointer

        usleep(config->g_delta_program);
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
