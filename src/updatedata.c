#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

static int extract_data(char *source_location, int length){
    int result = 0;
    for(int i = 0; i < length; i++){
        char c = source_location[i];
        result = result * 10 + (c - '0');
    }

    return result;
}

static void update_stats(
    struct proc_info_t *p_info,
    char *p_stats,
    char *exe,
    struct stat *file_stats,
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
    } stat_locations __attribute__((unused));

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
                        data->pid = extract_data(source_location, sub_length);
                        break;
                    case COMM:
                        memcpy(&data->comm, source_location, sub_length);
                        data->comm[sub_length] = '\0';
                        break;
                    case PPID:
                        data->ppid = extract_data(source_location, sub_length);
                        // memcpy(&data->ppid, source_location, sub_length);
                        break;
                    case START:
                        data->first_seen = extract_data(source_location, sub_length);
                        // memcpy(&data->first_seen, source_location, sub_length);
                        break;
                }

                // values that need to be set once
                data->exe_path = exe;
                data->file_size = file_stats->st_size;
                data->flags_table.not_missing = 1;
            }

            // values that need to be updated no matter what
            switch (stat_value_place) {
                case STATE:
                    // can't copy directly due to how the compiler
                    // works with bitfields
                    memcpy(&temp_state, source_location, sub_length);
                    data->flags_table.state = temp_state;
                    break;
                case CPU_U:
                    // memcpy(&cpu_u, source_location, sub_length);
                    cpu_u = extract_data(source_location, sub_length);
                    break;
                case CPU_S:
                    // memcpy(&cpu_s, source_location, sub_length);
                    cpu_s = extract_data(source_location, sub_length);
                    break;
                case START:

                    if(data->start_time == 0){
                        data->start_time = extract_data(source_location, sub_length);
                        // memcpy(&data->start_time, source_location, sub_length);
                    }

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
            if(fscanf(p_file, "%lf", &uptime) != 1){
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
                    while(isdigit(file[right_digit])){
                        right_digit++;
                    }

                    int total_length = right_digit - left_digit;

                    // memcpy(&data->mem_usage, &file[left_digit], total_length);
                    data->mem_usage = extract_data(&file[left_digit], total_length);
                }
            }

            fclose(p_file);

            // reading from file_stats from executible section
            // needs to be updated each time
            data->last_access = file_stats->st_atim.tv_sec;
            data->last_modified = file_stats->st_mtim.tv_sec;
            data->last_status = file_stats->st_ctim.tv_sec;

            //only set if its not old yet
            //
            //will remove later to decrease cpu usage
            //since this can be done on the client side
            if(data->last_access >= DEFAULT_OLD){
                data->flags_table.is_old = 1;
            }

            stat_value_place++;
            left_index = right_index + 1;
            right_index = left_index + 1;
        }

        right_index++;

    }
}
// index is the location in the main struct that the info should be updated
// if not there then it should be at the very end?
static int find_pid_index(struct proc_info_t *p_info, pid_t pid){
    for(size_t i = 0; i < p_info->proc_count; i++){
        if(p_info->data[i].pid == pid){
            return i;
        }
    }

    check_capacity(p_info);

    u_int32_t proc_next_index = p_info->proc_count;
    p_info->proc_count++;
    return proc_next_index;
}

static char *get_symlink_path(int pid){

    char path[32];
    char exe[1024];

    int written = snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    if(unlikely(written >= sizeof(path) || written < 0)){
        LOG("pid could not be added to /proc/[c]/exe");
        exit(EXIT_FAILURE);
    }

    ssize_t link_length = readlink(path, exe, sizeof(exe) - 1);

    if(unlikely(link_length == -1)){
        LOG("symlink could not be found");
        exit(EXIT_FAILURE);
    }

    exe[link_length] = '\0';
    char *symlink = calloc(1, link_length + 1);

    if(unlikely(symlink == NULL)){
        LOG("symlink could not be allocated");
        exit(EXIT_FAILURE);
    }

    memcpy(symlink, exe, link_length);

    return symlink;
}

int dir_filter(const struct dirent *dir){
    if(strcmp(dir->d_name,  ".") != 0 || strcmp(dir->d_name, "..") != 0){
        if(dir->d_type == DT_DIR && dir->d_type != DT_LNK && isdigit(dir->d_name[0])){
            return 1;
        }
    }

    return 0;
}

void scan_procs(struct thread_context_t *context){
    struct proc_info_t *p_info = context->p_proc_info;
    char p_dir[] = "/proc";

    if(unlikely(p_dir == NULL)) {
        LOG("could not create p_dir");
        exit(EXIT_FAILURE);
    }

    struct dirent **dir_list;
    int dir_num = scandir(p_dir, &dir_list, dir_filter, alphasort);

    if(unlikely(dir_num == -1)) {
        LOG("error using scandir");
        exit(EXIT_FAILURE);
    }

    for(size_t i = 0; i < dir_num; i++) {
        if(dir_list[i] != NULL){
            int pid = atoi(dir_list[i]->d_name);
            int index = find_pid_index(p_info, pid);

            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);

            char p_stats[256];

            char *p_exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat stats;
            struct stat *file_stats = &stats;

            if(unlikely(p_file == NULL)){
                LOG("could not open /proc/[pid]/stat");
                exit(EXIT_FAILURE);
            }

            if(fgets(p_stats, sizeof(p_stats) , p_file) && stat(p_exe, file_stats) == 0){
                update_stats(p_info, p_stats, p_exe, file_stats, index);
            }
            else {
                LOG("could not get info");
                exit(EXIT_FAILURE);
            }

            fclose(p_file);
        }

        free(dir_list[i]);
    }

    free(dir_list);
}
