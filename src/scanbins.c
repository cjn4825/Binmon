#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../include/logging.h"
#include "../include/bintypes.h"

static void craw_bins(struct bin_data_t *data, const char *bin_path){
    // once proccesses are scanned then it can manually craw /bin or /usr/bin or /tmp or user home
    // to find binaries

    struct dirent *p_info_bin;
    DIR *p_bin_dir = opendir(bin_path);
    struct stat stats;                  // not sure if this is right
    struct stat *file_stats = &stats;

    CHECK_ERROR(unlikely(p_bin_dir == NULL), "could not read bin_path location");

    while((p_info_bin = readdir(p_bin_dir)) != NULL){

        if(strcmp(p_info_bin->d_name, ".") == 0 || strcmp(p_info_bin->d_name, "..") == 0){
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", bin_path, p_info_bin->d_name);

        struct stat bin_stats;

        // lstat because I don't want to follow sym links
        if(lstat(path, &bin_stats) != 0){
            if(S_ISLNK(bin_stats.st_mode)){
                continue;
            }
        }

        if(S_ISDIR(bin_stats.st_mode)){
            craw_bins(data, path);
        }
        else if(S_ISREG(bin_stats.st_mode)){
            // this will be called for every 30 seconds in thread.c so this is right
            // just needs to put data in

            data->comm.t = COMM_TYPE;
            data->comm.l = strlen(p_info_bin->d_name);
            memcpy(&data->comm.v, &p_info_bin->d_name, strlen(p_info_bin->d_name));

            stat(path, file_stats);
            data->exe_path.t = EXE_TYPE;
            data->exe_path.l = strlen(path);
            memcpy(&data->exe_path.v, &path, strlen(path));

            data->last_access.t = ACCESS_TYPE;
            data->last_access.l = sizeof(file_stats->st_atim.tv_sec);
            data->last_access.v = file_stats->st_atim.tv_sec;

            data->last_status.t = STATUS_TYPE;
            data->last_status.l = sizeof(file_stats->st_ctim.tv_sec);
            data->last_status.v = file_stats->st_ctim.tv_sec;

            data->last_modified.t = MODIFIED_TYPE;
            data->last_modified.l = sizeof(file_stats->st_mtim.tv_sec);
            data->last_modified.v = file_stats->st_mtim.tv_sec;

            data->file_mode.t = FILE_MODE_TYPE;
            data->file_mode.l = sizeof(file_stats->st_mode);
            data->file_mode.v = file_stats->st_mode;

            // find way to get file creation time...using statx?

            data->file_size.t = FILE_SIZE_TYPE;
            data->file_size.l = sizeof(file_stats->st_size);
            data->file_size.v = file_stats->st_size;

            data++;
        }
    }

    closedir(p_bin_dir);
}

void scan_bins(void *offset_loc){
    struct bin_data_t *data = offset_loc;

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

    struct stat dir_stats;

    for(size_t i = 0; locations[i] != NULL; i++){
        if(stat(locations[i], &dir_stats) == 0){
            if(S_ISDIR(dir_stats.st_mode)){
                craw_bins(data, locations[i]);
            }
        }
        else {
            LOG("could not get stats of directory");
            exit(EXIT_FAILURE);
        }
    }
}
