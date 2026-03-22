#include <time.h>

// getting time for logs
void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}
