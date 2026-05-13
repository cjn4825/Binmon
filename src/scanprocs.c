#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

static int extract_data(char *source_location, int length){
    int result = 0;
    for(size_t i = 0; i < length; i++){
        char c = source_location[i];
        result = result * 10 + (c - '0');
    }

    return result;
}
static void update_stats(
    struct proc_data_t *data,
    char *p_stats,
    char *exe,
    struct stat *file_stats
){

    typedef enum {
        PID = 1,
        COMM = 2,
        STATE = 3,
        PPID = 4,
        CPU_U = 14,
        CPU_S = 15,
        START = 22
    } stat_location;

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

    while(right_index <= total_len - 1){

        char *right_location = &p_stats[right_index];

        if(*right_location == ' '){

            int sub_length = right_index - left_index;
            char *source_location = &p_stats[left_index];

            if(data->proc_flags.v.not_missing == 0){


                // this whole section is wrong since all the cases need to be meant once
                // but this loops only once
                switch (stat_value_place) {
                    case PID:
                        data->pid.t = PID_TYPE;
                        data->pid.l = sizeof(data->pid.v);
                        data->pid.v = extract_data(source_location, sub_length);
                        break;
                    case COMM:
                        data->comm.t = COMM_TYPE;
                        data->comm.l = strlen(data->comm.v);
                        memcpy(&data->comm.v, source_location, sub_length);
                        // data->comm.v[sub_length] = '\0';
                        // don't need null terminator with length
                        break;
                    case PPID:
                        data->ppid.t = PPID_TYPE;
                        data->ppid.v = extract_data(source_location, sub_length);
                        data->ppid.l = sizeof(data->ppid.v);
                        break;
                    case START:
                        // first seen too?
                        data->start_time.t = START_TYPE;
                        data->start_time.v = extract_data(source_location, sub_length);
                        data->start_time.l = sizeof(data->start_time.v);
                        break;
                }

                // values that need to be set once.. looks ugly i think
                data->exe_path.t = EXE_TYPE;
                data->exe_path.l = strlen(data->exe_path.v);
                memcpy(&data->exe_path.v, exe, strlen(data->exe_path.v));

                data->file_size.t = FILE_SIZE_TYPE;
                data->file_size.l = sizeof(data->file_size.v);
                data->file_size.v = file_stats->st_size;

                data->cpu_usage.t = CPU_TYPE;
                data->cpu_usage.l = sizeof(data->cpu_usage.v);

                data->mem_usage.t = MEM_TYPE;
                data->mem_usage.l = sizeof(data->mem_usage.v);

                data->last_access.t = ACCESS_TYPE;
                data->last_access.l = sizeof(data->last_access.v);

                data->last_modified.t = MODIFIED_TYPE;
                data->last_modified.l = sizeof(data->last_modified.v);

                data->last_status.t = STATUS_TYPE;
                data->last_status.l = sizeof(data->last_status.v);

                data->proc_flags.v.not_missing = 1;
            }

            // values that need to be updated no matter what
            switch (stat_value_place) {
                case STATE:
                    // can't copy directly due to how the compiler
                    // works with bitfields
                    data->proc_flags.t = FLAGS_TYPE;
                    data->proc_flags.l = sizeof(data->proc_flags.v);
                    memcpy(&temp_state, source_location, sub_length);
                    data->proc_flags.v.state = temp_state;
                    break;
                case CPU_U:
                    // cpu_u and cpu_s are used later to calculate cpu_usage
                    cpu_u = extract_data(source_location, sub_length);
                    break;
                case CPU_S:
                    cpu_s = extract_data(source_location, sub_length);
                    break;
                case START:

                    if(data->start_time.v == 0){
                        data->start_time.v = extract_data(source_location, sub_length);
                    }

                    break;
            }

            // cpu usage calculation
            FILE *p_file = fopen("/proc/uptime", "r");

            CHECK_ERROR(p_file == NULL, "failed to open /proc/uptime");

            // only want to scan the first one
            CHECK_ERROR(fscanf(p_file, "%lf", &uptime) != 1, "failed to scan /proc/uptime");

            long hertz = sysconf(_SC_CLK_TCK);
            double total_time = (cpu_u + cpu_s) / (double)hertz;
            double seconds = uptime - (start_time / (double)hertz);
            double cpu_usage = 100.0 * (total_time / seconds);

            data->cpu_usage.v = cpu_usage;

            // mem usage calculation
            char file[32];
            snprintf(file, sizeof(file),"/proc/%c/smaps_rollup", data->pid.v);

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

                    data->mem_usage.v = extract_data(&file[left_digit], total_length);
                }
            }

            fclose(p_file);

            // reading from file_stats from executible section
            // needs to be updated each time
            data->last_access.v = file_stats->st_atim.tv_sec;
            data->last_modified.v = file_stats->st_mtim.tv_sec;
            data->last_status.v = file_stats->st_ctim.tv_sec;

            if(data->last_access.v >= g_config->g_default_old){
                data->proc_flags.v.is_old = 1;
            }

            stat_value_place++;
            left_index = right_index + 1;
            right_index = left_index + 1;
        }

        right_index++;

    }
}

static char *get_symlink_path(int pid){

    char path[32];
    char exe[1024];

    int written = snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    CHECK_ERROR(
        unlikely(written >= sizeof(path) || written < 0),
        "pid could not be added to /proc/[c]/exe"
    );

    ssize_t link_length = readlink(path, exe, sizeof(exe) - 1);
    assert(link_length == strlen(exe));

    CHECK_ERROR(unlikely(link_length == -1), "symlink could not be found");

    char *symlink = calloc(1, link_length + 1);

    CHECK_ERROR(unlikely(symlink == NULL), "symlink could not be allocated");

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

void scan_procs(void *offset_loc){
    struct proc_data_t *data = (struct proc_data_t *)offset_loc;
    char p_dir[] = "/proc";

    struct dirent **dir_list;
    int dir_num = scandir(p_dir, &dir_list, dir_filter, alphasort);

    CHECK_ERROR(unlikely(dir_num == -1), "error using scandir");

    //
    //
    // needs to change so this returns info about reach process...not all the processes
    //
    //
    for(size_t i = 0; i < dir_num; i++) {
        if(dir_list[i] != NULL){
            int pid = atoi(dir_list[i]->d_name);

            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);

            char p_stats[256];

            char *p_exe = get_symlink_path(pid);
            FILE *p_file = fopen(path, "r");
            struct stat stats;
            struct stat *file_stats = &stats;

            CHECK_ERROR(unlikely(p_file == NULL), "could not open /proc/[pid]/stat");

            if(fgets(p_stats, sizeof(p_stats) , p_file) && stat(p_exe, file_stats) == 0){
                update_stats(data, p_stats, p_exe, file_stats);
            }
            else {
                LOG("could not get info");
                exit(EXIT_FAILURE);
            }
            free(p_exe);
            fclose(p_file);
        }

        free(dir_list[i]);
    }

    free(dir_list);
}
