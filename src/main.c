#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>

#include "../include/arena.h"
#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

//TODO:
//
//      notes in draw.io:
//          create areanas for proc and bin and pack
//
//          make uniform pack data..highlighed in diagram
//          ...pack data should just take in a type, value, and name
//          to fill in tlv's...make this a simple function that then
//          has a mutex...with this approach both proc and bin can use it
//          at the same time sort of...change it so binary and packet data
//          is put in the same packet...once full it will be sent out to
//          ring buffer and just set the offset pointer back to zero...this will rewrite
//          data until it gets formed to a packet again...
//
//
//cpu pinning with threads and thread affinity
//alignas for thread structs
//simd and vectorization
//switch to use atomic variables for number adjusting
//values in threads?
//
/// use const pointers such as arena *const ..
///
//figure out architecture to minimize code
//ring buffer
//make logging var in logging.h
//make yaml keys not dependent on order
//arena allocator
//add timing to packet header
//max out to 50 mb of memory usage then exit safely similar with cpu usage...
//integrate into areana allocator
//
//implement logging server
//ci/cd pipeline...valgrind and general linting...
//ebpf to replace parsing /proc
//virus total api with redis database
//tls certs with tcp connections
//finish bootstrap scripts and ansible
//update github page

int main(void){
    signal(SIGINT, handle_sigint);
    import_settings("../settings/settings.yml");
    set_logging();

    // move these to somewhere else???
    struct thread_context_t *const thread_context = calloc(1, sizeof(struct thread_context_t));
    init_context(thread_context);
    // test for core pinning threads
    // cpu_set_t cpuset;
    // CPU_ZERO(&cpuset);
    // CPU_SET(1,&cpuset);
    // int pin = pthread_setaffinity_np();

    pthread_t proc_thread, bin_thread, send_data_thread, heart_beat_thread, health_check_thread;
    // need to check if any creations failed...
    pthread_create(&bin_thread, NULL, create_proc_thread, thread_context);
    pthread_create(&proc_thread, NULL, create_bin_thread, thread_context);
    pthread_create(&send_data_thread, NULL, create_send_thread, thread_context);
    pthread_create(&heart_beat_thread, NULL, create_beat_thread, thread_context);
    pthread_create(&health_check_thread, NULL, create_healthbeat_thread, thread_context);

    pthread_join(proc_thread, NULL);
    pthread_join(bin_thread, NULL);

    destroy_mutexes(thread_context);
    free(thread_context);

    return 0;
}
