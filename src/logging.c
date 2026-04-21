#include "../include/logging.h"
#include "../include/settings.h"

void set_logging(void){
    if(g_log_value == 1){
        LOG("Agent starting in verbose debug mode...");
    }
}
