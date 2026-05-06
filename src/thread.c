#define _GNU_SOURCE
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
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
        // send_packet(context, BEAT);
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
    pin_thread(1, pthread_self());

    bin_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    // if mutexes arn't used then a context isn't needed here

    struct Arena *const arena_bin = create_arena();
    arena_bin->capacity = sizeof(arena_bin->pool); // change to yaml variable
    arena_bin->pool = alloc_arena(arena_bin, config->g_bin_pool_size);

    create_headers(arena_bin->pool);
    arena_bin->offset = sizeof(struct ether_header) + sizeof(struct iphdr);

    struct packet_header* prot = binmon_header(arena_bin->pool + arena_bin->offset);
    arena_bin->offset += sizeof(struct packet_header);

    prot->payload_length = arena_bin->offset - (size_t)arena_bin->pool;

    while(exit_flag == 0){
        scan_bins(arena_bin->pool + arena_bin->offset);

        prot->sequence++;
        prot->packet_type = BINARY_TYPE;
        // prot->time_stamp = get_log_time(char *buffer, size_t length);
        prot->crc = 0;///fix later

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
    arena_proc->capacity = sizeof(arena_proc->pool); // change to yaml var
    arena_proc->pool = alloc_arena(arena_proc, config->g_proc_pool_size);

    create_headers(arena_proc->pool);
    arena_proc->offset = sizeof(struct ether_header) + sizeof(struct iphdr);

    struct packet_header* prot;
    arena_proc->offset += sizeof(struct packet_header);

    prot->payload_length = arena_proc->offset - (size_t)arena_proc->pool;

    while(exit_flag == 0){
        prot = binmon_header(arena_proc->pool + arena_proc->offset);
        arena_proc->offset += sizeof(struct packet_header);

        scan_procs(arena_proc->pool + arena_proc->offset); // gets info about one process

        prot->payload_length += sizeof(struct proc_data_t);
        // prot->time_stamp = something
        prot->sequence++;
        prot->packet_type = PROC_TYPE;
        // prot->crc = 0;
        // adjust total size atomic value in main header...then just reset it
        // once done

        // push pointer to end of consumer pool
        CHECK_ERROR(
            (size_t)(arena_proc->pool + arena_proc->offset) +
            sizeof(struct proc_data_t) >= arena_proc->capacity,
            "arena proc filled capacity"
        );

        arena_proc->offset += sizeof(struct proc_data_t);
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
    arena_send->offset = 0;

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

    // not sure if i should use unlikely here???
    // if(unlikely(pthread_mutex_init(&thread_context->packet_header_lock, NULL) != 0)){
    //     LOG("Failed to create packet_header_lock mutex");
    //     exit(EXIT_FAILURE);
    // }
    CHECK_ERROR(unlikely(pthread_mutex_init(
        &thread_context->packet_header_lock, NULL) != 0),
        "Failed to create packet_header_lock mutex"
    );

    // should really consider if this check_error thing is actually worth it

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

    thread_context->socket_fd = server_connect();
}

void destroy_mutexes(struct thread_context_t *const mutex_context){
    pthread_mutex_destroy(&mutex_context->packet_header_lock);
    pthread_mutex_destroy(&mutex_context->pack_lock);
    pthread_mutex_destroy(&mutex_context->send_buffer_lock);
    pthread_mutex_destroy(&mutex_context->send_data_lock);
}
