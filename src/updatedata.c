#include <ctype.h>
#include <dirent.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/proctypes.h"

/*
*   detials about this file...
*
*
*/

void update_capacity(struct proc_info *p_info){
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

static void update_stats(
    struct proc_info *p_info,
    char *p_stats,
    char *exe,
    struct stat file_stats,
    size_t proc_index
){

    typedef enum {
        PID = 1,
        COMM = 2,
        STATE = 3,
        PPID = 4,
        CPU_U = 14,
        CPU_S = 15,
        START = 22
    } stat_locations;

    double uptime = 0;
    int left_index = 0;
    int right_index = 1;
    int total_len = strlen(p_stats);
    int cpu_u = 0;
    int cpu_s = 0;
    int start_time = 0;

    proc_data_t *data = &p_info->data[proc_index];

    // loops through /proc/.../stat to update info
    while(right_index <= total_len - 1){

        char *right_location = &p_stats[right_index];

        if(*right_location == ' '){

            int sub_length = right_index - left_index;
            char *source_location = &p_stats[left_index];

            // if its not seen before don't need to realloc?
            // no becaues the size is preallocated to 64

            if(proc_index == p_info->proc_count){
                switch (left_index) {
                    case PID:
                        memcpy(&data->pid, source_location, sub_length);
                        break;
                    case COMM:
                        memcpy(&data->comm, source_location, sub_length);
                        break;
                    case PPID:
                        memcpy(&data->ppid, source_location, sub_length);
                        break;
                    case START:
                        memcpy(&data->start_time, source_location, sub_length);
                        break;
                }
            }

            // values that need to be updated no matter what
            switch (left_index) {
                case STATE:
                    memcpy(&data->state, source_location, sub_length);
                    break;
                case CPU_U:
                    memcpy(&cpu_u, source_location, sub_length);
                    break;
                case CPU_S:
                    memcpy(&cpu_s, source_location, sub_length);
                    break;
            }

            // cpu usage calculation

            FILE *p_file = fopen("/proc/uptime", "r");

            if (!p_file) {
                perror("[DEBUG] Failed to open /proc/uptime");
                return;
            }

            // only want to scan the first one
            if(fscanf(p_file, "%lf", &uptime) != 1){
                perror("[DEBUG] Failed to scan /proc/uptime");
                return;
            }

            long hertz = sysconf(_SC_CLK_TCK);
            double total_time = (cpu_u + cpu_s) / (double)hertz;
            double seconds = uptime - (start_time / (double)hertz);
            double cpu_usage = 100.0 * (total_time / seconds);

            data->cpu_usage = cpu_usage;

            // mem usage calculation
            char file[32];
            snprintf(file, sizeof(file),"/proc/%c/smaps_rollup", data->pid);

            p_file = fopen(file, "r");

            // get pss value and set that equal to data->mem_usage everytime
            while(fgets(file, sizeof(file), p_file)){
                if(strncmp(file, "Pss:", 4) == 0){
                    int left_digit = 0;
                    while(!isdigit((char)file[left_digit])){
                        left_digit++;
                    }
                    // assume the value will be 4 digits for now
                    memcpy(&data->mem_usage, &file[left_digit], 4);
                }
            }

            fclose(p_file);

            left_index = right_index + 1;
            right_index = left_index + 1;
        }
        else{
            right_index++;
        }
    }

    // values updated list:
    // pid
    // comm
    // ppid
    // start_time
    // state
    // last_access
    // last_modified
    // is_old
    // exe_path
    // cpu_usage
    // mem_usage
    // previous_ran
    //      left to update:
    // first_seen
    // cpu_up
    // mem_up

    // reading from file_stats from executible section
    u_int64_t *current_last_access = &data->last_access;
    u_int64_t *current_last_modified = &data->last_modified;

    if(*current_last_access == 0){
        *current_last_access = file_stats.st_atim.tv_sec;
    }
    else {
        data->previous_ran = 1;
    }

    if(*current_last_modified == 0){
        *current_last_modified = file_stats.st_atim.tv_sec;
    }

    //only set if its not old yet
    if(*current_last_access >= DEFAULT_OLD){
        data->is_old = 1;
    }

    // sets exe path
    if(data->exe_path == 0){
        data->exe_path = exe;
    }

    // data->mem_table->mem_usage_1 =
    // if cpu/mem usage is a lot more than last time like 10 percent more
    // if(){
        // it then take the average and compare here
        // if its 10 percent greater or more then set
        // cpu_up to 1
        //
        // same for memory usage where it can also be used here
        //
        //
    // }
}

// index is the location in the main struct that the info should be updated
// if not there then it should be at the very end?
static int find_pid_index(struct proc_info *p_info, pid_t pid){
    for(size_t i = 0; i < p_info->proc_count; i++){
        if(p_info->data[i].pid == pid){
            return i;
        }
    }

    if(p_info->proc_count + 1 >= p_info->capacity){
        update_capacity(p_info);
    }

    // if no match then its new data
    // so the total needs to increase
    // by one then set the index to that
    p_info->data++;
    return p_info->proc_count;
}

static char *get_symlink_path(char pid){

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

void scan_procs(struct proc_info *p_info){
    DIR *p_dir = opendir("/proc");

    if(!p_dir) {
        perror("ERROR: could not read /proc");
        return;
    }

    struct dirent *p_entry;

    while((p_entry = readdir(p_dir)) != NULL) {

        // loops through each pid dir
        if(isdigit(p_entry->d_name[0])){
            pid_t pid = atoi(p_entry->d_name);
            int index = find_pid_index(p_info, pid);
            char path[PATH_MAX];
            char stats[256];

            snprintf(path, sizeof(path), "/proc/%s/stat", p_entry->d_name);

            char *p_exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat file_stats;

            if(p_file == NULL){
                return;
            }

            if(fgets(stats, sizeof(stat) , p_file) && stat(p_exe, &file_stats) == 0){
                stats[strcspn(stats, "\n")] = 0;
                update_stats(p_info, stats, p_exe, file_stats, index);
            }

            fclose(p_file);
        }
    }
    closedir(p_dir);
}
