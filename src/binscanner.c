#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

static void craw_bins(struct proc_info_t *p_info, const char *bin_path){
    // once proccesses are scanned then it can manually craw /bin or /usr/bin or /tmp or user home
    // to find binaries
    //
    // but doing this is expensive and makes it slow...for now just do this

    // search /bin
    struct dirent *p_info_bin;
    DIR *p_bin_dir = opendir(bin_path);

    if(unlikely(p_bin_dir == NULL)) {
        LOG("could not read bin_path location");
        exit(EXIT_FAILURE);
        return;
    }

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
            craw_bins(p_info, path);
        }
        else if(S_ISREG(bin_stats.st_mode)){
            for(size_t i = 0; i < p_info->proc_count; i++){

                char *exe_path = p_info->data[i].exe_path;
                char *d_name = p_info_bin->d_name;

                if(strncmp(exe_path, d_name, sizeof(*d_name)) != 0){

                    // since im sending this info every 30 seconds I don't need to worry about if its
                    // running or not since this is seperate...

                    check_capacity(p_info);

                    // u_int32_t proc_next_index = p_info->proc_count;

                    // since 0 is default value don't need to set pid
                    //
                    // have this so it builds its own struct...make its own instance then use the
                    // send_data function with a mutex?
                    //
                    //
                    // p_info->data[proc_next_index].exe_path = path;
                    // p_info->data[proc_next_index].last_access = bin_stats.st_atim.tv_sec;
                    // p_info->data[proc_next_index].last_modified = bin_stats.st_mtim.tv_sec;
                    // p_info->proc_count++;
                }
            }
        }
    }

    closedir(p_bin_dir);
}

void update_bins(struct thread_context_t *context){
    struct proc_info_t *p_info = context->p_bin_info;

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
                craw_bins(p_info, locations[i]);
            }
        }
        else {
            LOG("could not get stats of directory");
            exit(EXIT_FAILURE);
        }
    }
}
