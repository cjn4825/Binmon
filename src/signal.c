
#include "../include/signal.h"
#include <signal.h>

sig_atomic_t exit_flag = 0;

void handle_sigint(int sig){
    exit_flag = 1;
}
