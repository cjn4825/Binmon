#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>

#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

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
