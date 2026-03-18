#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "../include/proctypes.h"

struct proc_info* global_struct_ptr = NULL;
volatile sig_atomic_t exit_flag = 0;

// move this loggin logic to a headerfile?/.c file
// like a utils.c for just this function below
// and header for the macro
int g_logging = 0;

#define LOG(message, ...) \
    do { \
        if(g_logging) { \
            char time_buffer[10]; \
            get_log_time(time_buffer, sizeof(time_buffer)); \
            fprintf(stderr, "[%s][DEBUG] %s:%d | ", time_buffer, __FILE__, __LINE__); \
            fprintf(stderr, (message), ##__VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    }  while(0)

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

    p_info->data->cpu_table = malloc(sizeof(proc_cpu_usage_t));
    p_info->data->mem_table = malloc(sizeof(proc_mem_usage_t));

    // adjust for additional information added in headerfile

    // union needs to be malloced since another file will use it
    // tlv does not since it acts as a template
    return p_info;
}

int main(int argc, char *argv[]){

    // implement loggin more with a global macro?
    if(argc > 1 && strcmp(argv[1], "-v") == 0){
        g_logging = 1;
    }

    LOG("Agent starting in verbose debug mode...");

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
