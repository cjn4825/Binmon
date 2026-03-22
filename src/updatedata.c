#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proctypes.h"
#include "../include/logging.h"

static void check_capacity(struct proc_info *p_info){
    if(p_info->proc_count >= p_info->capacity * RESIZE_PERCENTAGE){
        size_t new_cap = p_info->capacity *= 2;

        p_info->data = realloc(p_info->data, new_cap);

        if(unlikely(p_info->data == NULL)){
            LOG("Data failed to resize from realloc");
            exit(EXIT_FAILURE);
        }

        size_t size_remaining = sizeof(proc_data_t) * (new_cap - p_info->proc_count);

        memset(&p_info->data[p_info->proc_count], '\0', size_remaining);

        p_info->capacity = new_cap;

    }
}

static void update_stats(
    struct proc_info *p_info,
    char *p_stats,
    char *exe,
    struct stat file_stats,
    int proc_index
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
    int stat_value_place = 1;

    // temp variable for bitfield value
    uint8_t temp_state;

    proc_data_t *data = &p_info->data[proc_index];

    while(right_index <= total_len - 1){

        char *right_location = &p_stats[right_index];

        if(*right_location == ' '){
            int sub_length = right_index - left_index;
            char *source_location = &p_stats[left_index];

            if(data->flags_table.not_missing == 0){

                switch (stat_value_place) {
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
                        memcpy(&data->first_seen, source_location, sub_length);
                        break;
                }

                // values that need to be set once
                data->exe_path = exe;
                data->file_size = file_stats.st_size;
                data->flags_table.not_missing = 1;
            }

            // values that need to be updated no matter what
            switch (stat_value_place) {
                case STATE:
                    // can't copy directly do to how the compiler
                    // works with bitfields
                    memcpy(&temp_state, source_location, sub_length);
                    data->flags_table.state = temp_state;
                    break;
                case CPU_U:
                    memcpy(&cpu_u, source_location, sub_length);
                    break;
                case CPU_S:
                    memcpy(&cpu_s, source_location, sub_length);
                    break;
                case START:


                    // makes this so it changes only if its different
                    //
                    //
                    memcpy(&data->start_time, source_location, sub_length);
                    break;
            }

            // cpu usage calculation

            FILE *p_file = fopen("/proc/uptime", "r");

            if (unlikely(p_file == NULL)) {
                LOG("failed to open /proc/uptime");
                exit(EXIT_FAILURE);
                return;
            }

            // only want to scan the first one
            if(unlikely(fscanf(p_file, "%lf", &uptime) != 1)){
                LOG("failed to scan /proc/uptime");
                exit(EXIT_FAILURE);
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

                    // counts number of digits until pss
                    // value is reached
                    int left_digit = 0;
                    while(!isdigit(file[left_digit])){
                        left_digit++;
                    }

                    int right_digit = left_digit;
                    while(isdigit(file[right_index])){
                        right_digit++;
                    }

                    int total_length = right_digit - left_digit;

                    memcpy(&data->mem_usage, &file[left_digit], total_length);
                }
            }

            fclose(p_file);

            // reading from file_stats from executible section
            // needs to be updated each time
            data->last_access = file_stats.st_atim.tv_sec;
            data->last_modified = file_stats.st_mtim.tv_sec;
            data->last_status = file_stats.st_ctim.tv_sec;

            //only set if its not old yet
            //
            //will remove later to decrease cpu usage
            //since this can be done on the client side
            if(data->last_access >= DEFAULT_OLD){
                data->flags_table.is_old = 1;
            }
        }

        stat_value_place++;
        left_index = right_index + 1;
        right_index = left_index + 1;
    }
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
        check_capacity(p_info);
    }

    u_int32_t proc_next_index = p_info->proc_count;
    p_info->proc_count++;
    return proc_next_index;
}

static char *get_symlink_path(char pid){

    char path[64];
    snprintf(path, sizeof(path),"/proc/%c/exe", pid);
    char *link = malloc(PATH_MAX);

    if(unlikely(link == NULL)){
        LOG("symlink could not be found");
        exit(EXIT_FAILURE);
    }

    int link_length = readlink(path, link, PATH_MAX - 1);

    if(unlikely(link_length == -1)){
        free(link);
        LOG("symlink could not be found");
        exit(EXIT_FAILURE);
    }

    link[link_length] = '\0';

    return link;
}

void craw_bins(struct proc_info *p_info, const char *bin_path){
    // once proccesses are scanned then it can manually craw /bin or /usr/bin or /tmp or user home
    // to find binaries

    // search /bin
    struct dirent *p_info_bin;
    DIR *p_bin_dir = opendir(bin_path);

    if(unlikely(p_bin_dir == NULL)) {
        LOG("could not read bin_path location");
        exit(EXIT_FAILURE);
        return;
    }

    while ((p_info_bin = readdir(p_bin_dir)) != NULL){
        // skip . and .. dirs
        if(strcmp(p_info_bin->d_name, ".") == 0 || strcmp(p_info_bin->d_name, "..") == 0){
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", bin_path, p_info_bin->d_name);

        struct stat bin_stats;

        // lstat because I don't want to follow sym links
        // ...think i also need to use S_ISLNK?
        if(lstat(path, &bin_stats) != 0){
            continue;
        }

        if(S_ISDIR(bin_stats.st_mode)){
            craw_bins(p_info, path);
        }
        else if(S_ISREG(bin_stats.st_mode)){

            // put logic here that checks if its already
            // in main struct
            for(size_t i = 0; i < p_info->proc_count; i++){

                char *exe_path = p_info->data[i].exe_path;
                char *d_name = p_info_bin->d_name;

                if(strncmp(exe_path, d_name, sizeof(*d_name)) != 0){

                    // if a bin is turned into a process then i also need to search
                    // if its a bin and delete that element?

                    check_capacity(p_info);

                    u_int32_t proc_next_index = p_info->proc_count;

                    p_info->data[proc_next_index].pid = 0;
                    p_info->data[proc_next_index].exe_path = path;
                    p_info->data[proc_next_index].last_access = bin_stats.st_atim.tv_sec;
                    p_info->proc_count++;
                }
            }

        }
    }

    closedir(p_bin_dir);
}

void scan_procs(struct proc_info *p_info){
    DIR *p_dir = opendir("/proc");

    if(unlikely(p_dir == NULL)) {
        LOG("could not read /proc");
        exit(EXIT_FAILURE);
        return;
    }

    struct dirent *p_entry;

    while((p_entry = readdir(p_dir)) != NULL) {

        if(isdigit(p_entry->d_name[0])){
            pid_t pid = atoi(p_entry->d_name);
            int index = find_pid_index(p_info, pid);
            char path[PATH_MAX];
            char *stats = calloc(1, STATS_LENGTH);

            snprintf(path, sizeof(path), "/proc/%s/stat", p_entry->d_name);

            char *p_exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat file_stats;

            if(unlikely(p_file == NULL)){
                LOG("could not open /proc/[pid]/stat");
                exit(EXIT_FAILURE);
                return;
            }

            if(fgets(stats, sizeof(stats) , p_file) && stat(p_exe, &file_stats) == 0){
                update_stats(p_info, stats, p_exe, file_stats, index);
                free(stats);
            }

            fclose(p_file);
        }

        const char *locations[] = {
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/local/bin",
            "/tmp",
            "/var/tmp",
            "/opt",
            "~/.local/bin",
            "~/Downloads",
            "/dev/shm",
            "~/bin",
            NULL
        };

        // also need to check if the directory exists or not
        //
        // make it so this scans only every 30 seconds or so for binaries
        //

        // don't like the approach with the null sentinal value but it works for now

        for(size_t i = 0; locations[i] != NULL; i++){
            craw_bins(p_info, locations[i]);
        }
    }

    closedir(p_dir);
}
