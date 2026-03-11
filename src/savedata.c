#include "../include/proctypes.h"
#include <inttypes.h>
#include <stdio.h>

/*
*   detials about this file...
*
*
*/

void save_state(struct proc_info *p_info){
    const char save_file[] = "registryinfo/registry.txt";
    FILE *p_save_file = fopen(save_file, "w");

    if(p_save_file == NULL) {
        perror("Error: Could not open registry.txt file.");
        return;
    }

    size_t proc_count = p_info->proc_count;

    proc_data_t *p_entry = &p_info->data[proc_count];

    while(p_info > 0){
        fprintf(
            p_save_file,
            "PID: %d \
            | NAME: %255s \
            | PPID: %d \
            | STARTUP_TIME: %lf \
            | FIRST_SEEN: %lf \
            | LAST_ACCESS: %"SCNu64" \
            | LAST_MODIFIED: %"SCNu64" \
            | CPU_USAGE: %lf%% \
            | MEM_USAGE: %lf%% \
            | RUNNING: %"SCNu8" \
            | PREVIOUS_RAN: %"SCNu8" \
            | CPU_UP: %"SCNu8" \
            | MEM_UP: %"SCNu8" \
            | IS_OLD: %"SCNu8" \
            | PATH: %1023s",
            p_entry->pid,
            p_entry->comm,
            p_entry->ppid,
            p_entry->start_time,
            p_entry->first_seen,
            p_entry->last_access,
            p_entry->last_modified,
            p_entry->cpu_usage,
            p_entry->mem_usage,
            p_entry->state,
            p_entry->previous_ran,
            p_entry->cpu_up,
            p_entry->mem_up,
            p_entry->is_old,
            p_entry->exe_path
            );
        proc_count--;
    }
    fclose(p_save_file);
}
