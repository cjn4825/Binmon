#include <ctype.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define MAX_BINARIES 100
#define DELTA_PROGRAM 100000
#define DELTA_SCAN 3.0

typedef struct{
    char name[256];
    int count;
} BinaryStats;

BinaryStats registry[MAX_BINARIES];
int totalTracked = 0;

void loadState(){
    char savefile[] = "registryinfo/registry.txt";
    FILE *pfile = fopen(savefile, "r");
    if(!pfile) return;

    char line[512];

    while (fgets(line, sizeof(line), pfile) && totalTracked < MAX_BINARIES) {
        if(sscanf(
            line,
            "Name: %s - count: %d",
            registry[totalTracked].name,
            &registry[totalTracked].count
        ) == 2){
            totalTracked++;
        }
    }
    fclose(pfile);
    printf("Loaded %d binaries from history.\n", totalTracked);
}

void saveState(){
    char savefile[] = "registryinfo/registry.txt";
    FILE *psaveFile = fopen(savefile, "w");
    if(psaveFile){
        for(int i = 0; i < totalTracked; i++){
            fprintf(
                psaveFile,
                "Name: %s - count: %d\n",
                registry[i].name,
                registry[i].count
            );
        }
        fclose(psaveFile);
    }

}

void handleSigint(int sig){
    printf("\nShutting down...\n");
    saveState();
    exit(0);
}

void updateStats(char* name){
    for(int i = 0; i < totalTracked; i++){
        if(strcmp(registry[i].name, name) == 0){
            registry[i].count++;
            return;
        }
    }

    if(totalTracked < MAX_BINARIES){
        strncpy(registry[totalTracked].name, name, 255);
        registry[totalTracked].count = 1;
        totalTracked++;
    }
}

void scanProcs(){
    DIR *pdir;
    struct dirent *pentry;

    pdir = opendir("/proc");
    if(pdir == NULL){
        perror("Could not open /proc/");
        return;
    }

    while ((pentry = readdir(pdir)) != NULL) {
        if(isdigit(pentry->d_name[0])){
            char path[256];
            char comm[256];

            snprintf(path, sizeof(path), "/proc/%s/comm", pentry->d_name);

            FILE *pfile = fopen(path, "r");
            if(pfile){
                if(fgets(comm, sizeof(comm) , pfile)){
                    comm[strcspn(comm, "\n")] = 0;
                    updateStats(comm);
                }
                fclose(pfile);
            }
        }
    }
    closedir(pdir);

}

int main(int argc, char* argv[]){
    signal(SIGINT, handleSigint);
    loadState();
    time_t start = time(NULL);
    time_t end;
    double diff;

    while (1) {
        scanProcs();
        time(&end);
        diff = difftime(end, start);

        if (diff >= DELTA_SCAN){
            time(&start);
            saveState();
        }
        usleep(DELTA_PROGRAM);
    }
    return 0;

}
