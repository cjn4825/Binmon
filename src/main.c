#include <ctype.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "../include/proctypes.h"

// TODO:
// finish duh

void *g_info = NULL;

/// only needs to update current data pointer in struct
void update_capacity(struct proc_info *p_info, size_t load_size){

    if(p_info->proc_count >= DEFAULT_MAX){
        int new_size = 128;
        while(new_size <= p_info->proc_count){
            new_size *= 2;
        }

        proc_data_t *p_resize_data = realloc(p_info->data, new_size);

        if(p_resize_data){
            p_info->data = p_resize_data;
            p_info->capacity = new_size;
        }
        else{
            perror("ERROR: realloc failed");
        }
    }
}

void load_state(struct proc_info *p_info){
    char save_file[] = "registryinfo/registry.txt";
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
            | TOTAL_AGE: %"SCNu64" \
            | FIRST_SEEN: %"SCNu64" \
            | LAST_ACCESS: %"SCNu64" \
            | AVG_CPU: %lf%% \
            | AVG_MEM: %lf%% \
            | RUNNING: %c \
            | CPU_UP: %"SCNu8" \
            | MEM_UP: %"SCNu8" \
            | PATH: %1023s",
            &p_entry->pid,
            t_comm,
            &p_entry->ppid,
            &p_entry->first_seen,
            &p_entry->first_seen,
            &p_entry->last_access,
            &p_entry->cpu_usage,
            &p_entry->mem_usage,
            &p_entry->is_running,
            &p_entry->cpu_is_increasing,
            &p_entry->mem_is_increasing,
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

void save_state(struct proc_info *p_info){
    char save_file[] = "registryinfo/registry.txt";
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
            | TOTAL_AGE: %"SCNu64" \
            | FIRST_SEEN: %"SCNu64" \
            | LAST_ACCESS: %"SCNu64" \
            | AVG_CPU: %lf%% \
            | AVG_MEM: %lf%% \
            | RUNNING: %c \
            | CPU_UP: %"SCNu8" \
            | MEM_UP: %"SCNu8" \
            | PATH: %1023s",
            p_entry->pid,
            p_entry->comm,
            p_entry->ppid,
            p_entry->first_seen,
            p_entry->first_seen,
            p_entry->last_access,
            p_entry->cpu_usage,
            p_entry->mem_usage,
            p_entry->is_running,
            p_entry->cpu_is_increasing,
            p_entry->mem_is_increasing,
            p_entry->exe_path
            );
        proc_count--;
    }
    fclose(p_save_file);
}

void handle_sigint(int sig){
    if (g_info != NULL) {
        save_state((struct proc_info*)g_info);
        printf("\n[DEBUG] Shutting down...\n");
        exit(0);
    }
}

char *get_symlink_path(pid_t pid){

    char path[64];
    snprintf(path, sizeof(path),"/proc/%d/exe", pid);
    char *link = malloc(PATH_MAX);

    if(link == NULL){
        return NULL;
    }

    size_t link_length = readlink(path, link, PATH_MAX - 1);

    if(link_length == -1){
        free(link);
        perror("[DEBUG] Could not find link");
        return NULL;
    }

    link[link_length] = '\0';

    return link;
}

//////////////////////make sure to free the link after its been used

// update to include other values?
void update_stats(struct proc_info *p_info, char *p_pid){

    typedef enum {
        PID = 1,
        COMM = 2,
        STATE = 3,
        PPID = 4,
    } stat_locations;
    for(size_t i = 0; i < p_info->proc_count; i++){

    }

    // set values of p_info based on enum positions
}

// if st_atime is more than 30 days then it can be
// flagged with another field in the proc_info

// get avg cpu and mem usage also so that
// a flag could be made where if the cpu or mem
// usage has increase by say 10 percent then another field
// gets added

// first_seen = if new process then that is the time..
// else its the first calculated first_seen

// total_time = utime + stime
// seconds = uptime - (starttime / Hertz)
// cpu_usage = 100 * ((total_time / Hertz) / seconds)

void update_exe(struct proc_info *p_info, char* exe){
    struct stat file_stats;
    if(stat(exe, &file_stats) == 0){
        for(size_t i = 0; i < p_info->proc_count; i++){

            u_int64_t last_access = p_info->data[i].last_access;
            u_int64_t last_modified = p_info->data[i].last_modified;

            if(last_access == 0){
                last_access = file_stats.st_atim.tv_sec;
            }
            else if(last_modified == 0){
                last_modified = file_stats.st_mtim.tv_sec;
            }

            if(last_access >= DEFAULT_OLD){
                p_info->data->is_old = 1;
            }
        }
    }
}

void scan_procs(struct proc_info *p_info){
    DIR *p_dir = opendir("/proc");

    if(!p_dir) {
        perror("ERROR: could not read /proc");
        return;
    }

    struct dirent *p_entry;

    while ((p_entry = readdir(p_dir)) != NULL) {
        if(isdigit(p_entry->d_name[0])){

            // create grouping of pid values 
            // where they can be passed around 
            // to different functions and this will be 
            // dynamically updated here
            char pid = p_entry->d_name[0];
            char path[PATH_MAX];
            char stat[256];

            snprintf(path, sizeof(path), "/proc/%s/stat", p_entry->d_name);

            char *exe = get_symlink_path((pid_t)pid);
            update_exe(p_info, exe);

            FILE *p_file = fopen(path, "r");
            if(p_file){
                if(fgets(stat, sizeof(stat) , p_file)){
                    stat[strcspn(stat, "\n")] = 0;
                    update_stats(p_info, stat);
                }
                fclose(p_file);
            }
        }
    }
    closedir(p_dir);
}

struct proc_info* create_info(){

    struct proc_info *p_info = malloc(sizeof(struct proc_info));

    if(!p_info){
        perror("Error: Could not malloc proc_info");
        return NULL;
    }

    p_info->capacity = DEFAULT_MAX;

    p_info->data = malloc(sizeof(struct proc_info) * p_info->capacity);

    return p_info;
}

int main(void){
    struct proc_info *p_info = create_info();
    g_info = p_info;
    signal(SIGINT, handle_sigint);
    load_state(p_info);

    time_t start_time = time(NULL);
    time_t current_time;
    double diff_time;

    while (1) {
        scan_procs(p_info);
        current_time = time(NULL);
        diff_time = difftime(current_time, start_time);

        if (diff_time >= DELTA_SCAN){
            time(&start_time);
            save_state(p_info);
            start_time = current_time;
        }
        usleep(DELTA_PROGRAM);
    }

    // shouldn't this be freed once a interupt happens
    // because this would never run right?
    free(p_info->data);
    free(p_info);

    return 0;
}
