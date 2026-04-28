
#include "../include/signal.h"
#include <signal.h>

extern sig_atomic_t exit_flag;

void handle_sigint(int sig){
    while(g_finished != 1){
        exit_flag = 1;
    }
}
