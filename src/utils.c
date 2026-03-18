#include <stdio.h>
#include <time.h>

// #include "../include/proctypes.h"

// used for logging
void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}

// used for getting time of a specific proccess
// in ISO 8701 standard e.g. 2026/03/18 14:10

// char[] get_process_time(){

//     snprintf();
//     return;
// }
