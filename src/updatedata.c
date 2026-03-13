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


static pid_t find_pid_index(struct proc_info *p_info, pid_t pid){
    for(size_t i = 0; i < p_info->proc_count; i++){
        if(p_info->data[i].pid == pid){
            return pid;
        }
        else{
            return p_info->proc_count;
            p_info->data++;
        }
    }
    return pid;
}

static void update_stats(
    struct proc_info *p_info,
    const char *p_stats,
    const char *exe,
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

    int left_index = 0;
    int right_index = 1;
    int total_len = strlen(p_stats);
    int var_index = 0;
    int cpu_u = 0;
    int cpu_s = 0;
    int start_time = 0;

    // not right as well?
    proc_data_t data = p_info->data[proc_index];

    while(right_index <= total_len - 1){
        if(*(p_stats + right_index) == ' '){

            int sub_length = right_index - left_index;
            int source = *(p_stats + left_index);

            // values updated only when its first seen
            if(proc_index == p_info->proc_count + 1){
                switch (var_index) {
                    case PID:
                        memcpy(&data.pid, &source, sub_length);
                        break;
                    case COMM:
                        memcpy(&data.comm, &source, sub_length);
                        break;
                    case PPID:
                        memcpy(&data.ppid, &source, sub_length);
                        break;
                    case START:
                        memcpy(&data.start_time, &source, sub_length);
                        break;
                }
            }

            // values that need to be updated no matter what
            switch (var_index) {
                case STATE:
                    memcpy(&data.state, &source, sub_length);
                    break;
                case CPU_U:
                    memcpy(&cpu_u, &source, sub_length);
                    break;
                case CPU_S:
                    memcpy(&cpu_s, &source, sub_length);
                    break;
            }

            // this isn't right i think
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

            memcpy(&data.cpu_usage, &source, sub_length);

            var_index++;
            left_index = right_index;
        }
        else{
            right_index++;
        }
        right_index++;
    }

    u_int64_t *current_last_access = &data.last_access;
    u_int64_t *current_last_modified = &data.last_modified;

    if(*current_last_access == 0 && *current_last_modified == 0){
        *current_last_access = file_stats.st_atim.tv_sec;
        *current_last_modified = file_stats.st_atim.tv_sec;
    }

    //only set if its not old yet
    if(*current_last_access >= DEFAULT_OLD){
        data.is_old = 1;
    }

    // if its previously been accessed
    if(*current_last_access != 0){
        data.is_old = 1;
    }

    // sets exe path
    if(data.exe_path == 0){
        data.exe_path = exe;
    }

    // if cpu/mem usage is a lot more than last time like 10 percent more
    if(data.cpu_usage){
        // malloc a 10 proc_data_t size and add elements to
        // it then take the average and compare here
        // if its 10 percent greater or more then set
        // cpu_up to 1
        //
        // same for memory usage where it can also be used here
        //
        //
    }
}

static const char *get_symlink_path(char pid){

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
        if(isdigit(p_entry->d_name[0])){
            pid_t pid = atoi(p_entry->d_name);
            int index = find_pid_index(p_info, pid);
            char path[PATH_MAX];
            char stats[256];

            snprintf(path, sizeof(path), "/proc/%s/stat", p_entry->d_name);

            const char *p_exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat file_stats;

            if(p_file){
                if(fgets(stats, sizeof(stat) , p_file) && stat(p_exe, &file_stats) == 0){
                    stats[strcspn(stats, "\n")] = 0;
                    update_stats(p_info, stats, p_exe, file_stats, index);
                    // free(p_exe);
                }
                fclose(p_file);
            }
        }
    }
    closedir(p_dir);
}
