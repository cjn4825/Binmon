#define _GNU_SOURCE
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/thread.h"
#include "../include/arena.h"
#include "../include/create_headers.h"
#include "../include/settings.h"
#include "../include/proctypes.h"
#include "../include/bintypes.h"
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




    // once data is written set it in_use = 1


    bin_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;
    // if mutexes arn't used then a context isn't needed here

    struct Arena *const arena_bin = create_arena();
    arena_bin->capacity = sizeof(arena_bin->pool); // change to yaml variable
    arena_bin->pool = alloc_arena(arena_bin, config->g_bin_pool_size);
    context->pool_bin = arena_bin->pool;

    create_headers(arena_bin->pool);
    arena_bin->offset = sizeof(struct ether_header) + sizeof(struct iphdr);

    struct packet_header* prot = binmon_header(arena_bin->pool + arena_bin->offset);
    arena_bin->offset += sizeof(struct packet_header);

    prot->payload_length = arena_bin->offset - (size_t)arena_bin->pool;
    prot->packet_type = BINARY_TYPE;

    while(exit_flag == 0){
        scan_bins(arena_bin->pool + arena_bin->offset);

        prot->sequence++;
        // prot->time_stamp = get_log_time(char *buffer, size_t length);
        prot->crc = 0;///fix later

        send_push(context->queue_bin, arena_bin->pool + arena_bin->offset);

        sleep(config->g_bin_scan_time);
    }

    return NULL;
}
// goal is to add proces values as fast as possible to the pool
void* create_proc_thread(void *context_arg){





    // once data is written set it in_use = 1



    pin_thread(2, pthread_self());
    proc_status = 1;

    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    struct Arena *const arena_proc = create_arena();
    arena_proc->capacity = sizeof(arena_proc->pool); // change to yaml var
    arena_proc->pool = alloc_arena(arena_proc, config->g_proc_pool_size);
    context->pool_proc = arena_proc->pool;

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

        send_push(context->queue_proc, arena_proc->pool + arena_proc->offset);
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
    pin_thread(3, pthread_self()); // should i even pin this?
    send_status = 1;
    struct thread_context_t *const context = (struct thread_context_t *const)context_arg;

    context->queue_proc = send_init();
    context->queue_bin = send_init();

    void* data = NULL;

    while(exit_flag == 0){

        if(send_pop(context->queue_proc, &data)){
            // send the data to af_xdp ring buffer
        }
        else if(send_pop(context->queue_bin, data)){
            // send the data to af_xdp ring buffer
        }

        usleep(config->g_delta_program);
    }

    return NULL;
}

void init_context(struct thread_context_t *const thread_context){

    // had mutex info as well but removed since i don't think i need
    // them anymore
    thread_context->socket_fd = server_connect();
}

void destroy_mutexes(struct thread_context_t *const mutex_context){
    // same as above
}
