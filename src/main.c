#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

//TODO:
//figure out architecture to minimize code
//ring buffer
//make logging var in logging.h
//make yaml keys not dependent on order
//arena allocator
//add timing to packet header
//max out to 50 mb of memory usage then exit safely similar with cpu usage...integrate into areana allocator
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

    struct thread_context_t *thread_context = calloc(1, sizeof(struct thread_context_t));
    init_context(thread_context);

    pthread_t proc_thread, bin_thread, send_data_thread, heart_beat_thread, health_check_thread;

    pthread_create(&bin_thread, NULL, create_proc_thread, thread_context);
    pthread_create(&proc_thread, NULL, create_bin_thread, thread_context);
    pthread_create(&send_data_thread, NULL, create_send_thread, thread_context);
    pthread_create(&heart_beat_thread, NULL, create_beat_thread, thread_context);
    // create one for health check thread that checks statuses of all other threads

    pthread_join(proc_thread, NULL);
    pthread_join(bin_thread, NULL);

    destroy_mutexes(thread_context);
    free(thread_context);

    return 0;
}
