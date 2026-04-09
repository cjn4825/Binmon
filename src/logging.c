#include "../include/logging.h"
#include "../include/settings.h"

int g_logging = LOG_VALUE;

void log_program(void){
    if(g_logging == 1){
        LOG("Agent starting in verbose debug mode...");
    }
}
