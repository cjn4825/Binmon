#include <cstddef>
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
            | FIRST_SEEN: %"SCNu64" \
            | LAST_ACCESS: %"SCNu64" \
            | LAST_MODIFIED: %"SCNu64" \
            | CPU_USAGE: %lf%% \
            | MEM_USAGE: %lf%% \
            | RUNNING: %c \
            | PREVIOUS_RAN: %c \
            | CPU_UP: %"SCNu8" \
            | MEM_UP: %"SCNu8" \
            | IS_OLD: %c \
            | PATH: %1023s",
            &p_entry->pid,
            t_comm,
            &p_entry->ppid,
            &p_entry->first_seen,
            &p_entry->last_access,
            &p_entry->last_modified,
            &p_entry->cpu_usage,
            &p_entry->mem_usage,
            &p_entry->is_running,
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
            | FIRST_SEEN: %"SCNu64" \
            | LAST_ACCESS: %"SCNu64" \
            | LAST_MODIFIED: %"SCNu64" \
            | CPU_USAGE: %lf%% \
            | MEM_USAGE: %lf%% \
            | RUNNING: %c \
            | PREVIOUS_RAN: %c \
            | CPU_UP: %"SCNu8" \
            | MEM_UP: %"SCNu8" \
            | IS_OLD: %c \
            | PATH: %1023s",
            p_entry->pid,
            p_entry->comm,
            p_entry->ppid,
            p_entry->first_seen,
            p_entry->last_access,
            p_entry->last_modified,
            p_entry->cpu_usage,
            p_entry->mem_usage,
            p_entry->is_running,
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

void handle_sigint(int sig){
    if (g_info != NULL) {
        save_state((struct proc_info*)g_info);
        printf("\n[DEBUG] Shutting down...\n");
        exit(0);
    }
}

char *get_symlink_path(char pid){

    char path[64];
    snprintf(path, sizeof(path),"/proc/%c/exe", pid);
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
void update_stats(struct proc_info *p_info, char *p_stats, char *exe, struct stat file_stats){

    typedef enum {
        PID = 1,
        COMM = 2,
        STATE = 3,
        PPID = 4,
        CPU_U = 14,
        CPU_S = 15,
        START = 22
    } stat_locations;

    int left_index = 0;
    int right_index = 1;
    int total_len = strlen(p_stats);
    int var_index = 0;
    int process_index = 0;
    int cpu_u = 0;
    int cpu_s = 0;
    int start_time = 0;

    while(process_index <= p_info->proc_count){
        while(right_index <= total_len){
            if(*(p_stats + right_index) == ' '){

                int sub_length = right_index - left_index;
                int source = *(p_stats + left_index);

                switch (var_index) {
                    case PID:
                        memcpy(&p_info->data[process_index].pid, &source, sub_length);
                        break;
                    case COMM:
                        memcpy(&p_info->data[process_index].comm, &source, sub_length);
                        break;
                    case STATE:
                        memcpy(&p_info->data[process_index].state, &source, sub_length);
                        break;
                    case PPID:
                        memcpy(&p_info->data[process_index].ppid, &source, sub_length);
                        break;
                    case START:
                        memcpy(&p_info->data[process_index].start, &source, sub_length);
                        break;
                    case CPU_U:
                        memcpy(&cpu_u, &source, sub_length);
                        break;
                    case CPU_S:
                        memcpy(&cpu_s, &source, sub_length);
                        break;
                }

                if(cpu_u != 0 && cpu_s != 0){

                    FILE *fp = fopen(p_stats, "r");
                    fp = fopen("/proc/uptime", "r");

                    double uptime = 0;

                    if (!fp) {
                        perror("[DEBUG] Failed to open /proc/uptime");
                    }

                    fscanf(fp, "%lf", &uptime);
                    fclose(fp);

                    long hertz = sysconf(_SC_CLK_TCK);
                    double total_time = (cpu_u + cpu_s) / (double)hertz;
                    double seconds = uptime - (start_time / (double)hertz);
                    double cpu_usage = 100.0 * (total_time / seconds);

                    memcpy(&p_info->data[process_index].cpu_usage, &source, sub_length);

                    cpu_u = 0;
                    cpu_s = 0;
                }

                var_index++;
                left_index = right_index;
            }
            else{
                right_index++;
            }
            right_index++;
        }

        u_int64_t *current_last_access = &p_info->data[process_index].last_access;
        u_int64_t *current_last_modified = &p_info->data[process_index].last_modified;

        if(*current_last_access == 0 && *current_last_modified == 0){
            *current_last_access = file_stats.st_atim.tv_sec;
            *current_last_modified = file_stats.st_atim.tv_sec;
        }
        else {
            p_info->data[process_index + 1].last_access = file_stats.st_atim.tv_sec;
            p_info->data[process_index + 1].last_access = file_stats.st_atim.tv_sec;

            // first_seen if it hasn't been seen before
            // on first load_state if the data hasn' been seen before in the
            // load then set this to 1

            p_info->proc_count++;
        }

        // if its old
        if(*current_last_access >= DEFAULT_OLD){
            p_info->data[process_index].is_old = 1;
        }

        // if its previously been accessed
        if(*current_last_access != 0){
            p_info->data[process_index].is_old = 1;
        }

        // sets exe path
        if(p_info->data[process_index].exe_path == 0){
            p_info->data[process_index].exe_path = exe;
        }

        // if cpu/mem usage is a lot more than last time like 10 percent more
        if(p_info->data[process_index].cpu_usage){
            // malloc a 10 proc_data_t size and add elements to
            // it then take the average and compare here
            // if its 10 percent greater or more then set
            // cpu_up to 1
            //
            // same for memory usage where it can also be used here
            //
            //
        }


        // go through all fields to make sure they are included

        process_index++;
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

            char pid = p_entry->d_name[0];
            char path[PATH_MAX];
            char stats[256];

            snprintf(path, sizeof(path), "/proc/%s/stat", p_entry->d_name);

            char *exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat file_stats;

            if(p_file){
                if(fgets(stats, sizeof(stat) , p_file) && stat(exe, &file_stats) == 0){
                    stats[strcspn(stats, "\n")] = 0;
                    update_stats(p_info, stats, exe, file_stats);
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

    p_info->data = malloc(sizeof(proc_data_t) * p_info->capacity);

    return p_info;
}

int main(void){
    struct proc_info *p_info = create_info();
    g_info = p_info;
    signal(SIGINT, handle_sigint); // learn how this works
    load_state(p_info);

    time_t start_time = time(NULL);
    time_t current_time;
    double diff_time;

    while(1) {
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
