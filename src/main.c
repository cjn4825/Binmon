#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

//TODO:
//finish bootstrap scripts and ansible
//add timing to packet header
//max out to 50 mb of memory usage then exit safely similar with cpu usage
//implement logging server
//implement yaml settings to replace macros in settings.h file
//ci/cd pipeline...valgrind and general linting...
//ebpf to replace parsing /proc
//virus total api with redis database
//tls certs with tcp connections
//change architecture for better cpu cache usage
//update github page

int main(void){
    signal(SIGINT, handle_sigint);
    log_program(); // rename to make more sense

    struct thread_context_t *thread_context = calloc(1, sizeof(struct thread_context_t));
    init_context(thread_context);

    pthread_t proc_thread;
    pthread_t bin_thread;
    pthread_t send_data_thread;
    pthread_t heart_beat_thread;
    pthread_t health_check_thread;

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
