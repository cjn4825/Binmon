#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../include/proctypes.h"
extern void update_capacity(struct proc_info *p_info, size_t load_size);

/*
*   detials about this file...
*
*
*/

void load_state(struct proc_info *p_info){
    const char save_file[] = "registryinfo/registry.txt";
    FILE *p_file = fopen(save_file, "r");

    if(p_file == NULL){
        perror("Error: Could not open registry.txt file.");
        return;
    }

    char line[4096];
    char t_comm[256], t_path[1024];

    while (fgets(line, sizeof(line), p_file)) {
        size_t proc_count = p_info->proc_count;
        proc_data_t *p_entry = &p_info->data[proc_count];

        int num_entry = sscanf(
            line,
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
            &p_entry->pid,
            t_comm,
            &p_entry->ppid,
            &p_entry->start_time,
            &p_entry->first_seen,
            &p_entry->last_access,
            &p_entry->last_modified,
            &p_entry->cpu_usage,
            &p_entry->mem_usage,
            &p_entry->state,
            &p_entry->previous_ran,
            &p_entry->cpu_up,
            &p_entry->mem_up,
            &p_entry->is_old,
            t_path
        );

        if(num_entry == 12){
            p_entry->exe_path = strdup(t_path);
            p_entry->comm = strdup(t_comm);
        }
        else {
            perror("ERROR: failed to load data during");
        }

        proc_count++;
    }

    update_capacity(p_info, p_info->proc_count);

    fclose(p_file);
    printf("[DEBUG] Loaded %lu binaries from history.\n", p_info->proc_count);
}
