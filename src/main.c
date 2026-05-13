#include <pthread.h>
#include <stdlib.h>

#include "../include/utils.h"
#include "../include/logging.h"
#include "../include/signal.h"
#include "../include/thread.h"

//TODO:
/*  put mem allocations in main before program starts
 *  expand on thread context struct to be used for that
 */
// // finish producer consumer code
//      // make sure that if a structure has variables that are modified
//      // by multiple threads that they are not in the same cache line
//      // with alignas(64)
// // switch to timer_fd create instead of sleep
//
//log telemtry such as packet count...data size ect...atomic featch add for this
//ring buffer...use af_xdp
//max out to 50 mb of memory usage then exit safely similar with cpu usage...
//
//implement logging server
//ci/cd pipeline...valgrind and general linting...
//ebpf to replace parsing /proc
//virus total api with redis database
//tls certs with tcp connections
//finish bootstrap scripts and ansible
//io_uring implementation
//update github page

int main(void){
    signal(SIGINT, handle_sigint);
    import_settings("../settings/settings.yml");
    set_logging();

    struct thread_context_t *const thread_context = calloc(1, sizeof(struct thread_context_t));
    init_context(thread_context);

    pthread_t proc_thread, bin_thread, send_data_thread, heart_beat_thread, health_check_thread;
    CREATE_THREAD(bin_thread, create_proc_thread);
    CREATE_THREAD(proc_thread, create_bin_thread);
    CREATE_THREAD(send_data_thread, create_send_thread);
    CREATE_THREAD(heart_beat_thread, create_beat_thread);
    CREATE_THREAD(health_check_thread, create_healthbeat_thread);

    pthread_join(proc_thread, NULL);
    pthread_join(bin_thread, NULL);
    pthread_join(send_data_thread, NULL);
    pthread_join(heart_beat_thread, NULL);
    pthread_join(health_check_thread, NULL);

    free(thread_context);

    return 0;
}
