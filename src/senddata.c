// #include <arpa/inet.h>
// #include <pthread.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>

// #include "../include/proctypes.h"
// #include "../include/logging.h"
// #include "../include/thread.h"
#include "../include/settings.h"
#include "../include/send_data.h"

struct send_queue* send_init(){
    struct send_queue* q = malloc(sizeof(struct send_queue));
    q->pool = malloc(g_config->g_send_pool_size);

    atomic_init(&q->head, 0); // might need to move these to the main thread?
    atomic_init(&q->tail, 0);

    // also need to make all malloc calls done before the program really starts as in before the threads start

    return q;

}

int send_push(struct send_queue* q, void* data){

    // isn't tail not updated? why... also i don't think this makes sense since im just reading
    // and i don't think this gets updated?

    size_t curr_tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t curr_head = atomic_load_explicit(&q->head, memory_order_acquire);

    if(curr_tail - curr_head >= g_config->g_send_pool_size){
        return -1;
    }

    data = (void*)((size_t)(q->pool + curr_tail) & (g_config->g_send_pool_size - 1));

    // why not use atomic_fetch_add_explicit?
    atomic_store_explicit(&q->tail, curr_tail++, memory_order_release);
    return 0;

}

int send_pop(struct send_queue* q, void** out_data){
    size_t curr_head = atomic_load_explicit(&q->head, memory_order_relaxed);
    size_t curr_tail = atomic_load_explicit(&q->tail, memory_order_acquire);

    if(curr_head == curr_tail){
        return -1;
    }

    // why void** and & don't remember
    *out_data = (void**)((size_t)(q->pool + curr_head) & (g_config->g_send_pool_size - 1));

    atomic_store_explicit(&q->head, curr_head++, memory_order_release);
    return 0;
}
