#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "../include/proctypes.h"

struct proc_info* global_struct_ptr = NULL;
volatile sig_atomic_t exit_flag = 0;

static void handle_sigint(int sig){
    if (global_struct_ptr != NULL) {
        save_state(global_struct_ptr); // how does this point to the original one? put in notes
        global_struct_ptr = NULL;
        exit(0);
    }
}

static struct proc_info* create_info(){

    struct proc_info *p_info = malloc(sizeof(struct proc_info));

    if(!p_info){
        perror("Error: Could not malloc proc_info");
        return NULL;
    }

    p_info->capacity = DEFAULT_MAX;

    p_info->data = malloc(sizeof(proc_data_t) * p_info->capacity);

    return p_info;
}

int main(void){
    struct proc_info *p_info = create_info();
    global_struct_ptr = p_info;
    signal(SIGINT, handle_sigint);
    load_state(p_info);

    double diff_time;

    while(!exit_flag) {
        scan_procs(p_info);
        save_state(p_info);
        usleep(DELTA_PROGRAM);
    }

    return 0;
}
