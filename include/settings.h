#ifndef SETTINGS_H
#define SETTINGS_H

// integrate into yaml file configuration

// #define LOG_VALUE 1                 // turn logging on
// #define PORT 9000                   // port where client is listening on
// #define SERVER_ADDRESS "127.0.0.1"  // server address (this is the server)
// #define DELTA_PROGRAM 100           // tick rate of the program in miliseconds
// #define RESIZE_PERCENTAGE .90       // What percent full until resizing
// #define DEFAULT_OLD 2592000         // how many days in seconds until a process is old(30 days)
// #define DEFAULT_MAX 1024            // default size of max procs before relloc
// #define STATS_LENGTH 256            // lenght of stats of each process
// #define BIN_SCAN_TIME 60            // amount of time in seconds that the bin scan happens
// #define HEALTH_SCAN_TIME 5          // amount of time in seconds for health check for each thread
// #define BEAT_SCAN_TIME 20           // amount of time in seconds for alive check for each instance

// probably wont need these anymore
#define PROC 1
#define BIN 2
#define BEAT 3


struct Config {
    int g_port;
    int g_delta_program;
    int g_resize_percentage;
    int g_proc_pool_size;
    int g_bin_pool_size;
    int g_send_pool_size;
    int g_default_old;
    int g_default_max;
    int g_stats_length;
    int g_bin_scan_time;
    int g_health_scan_time;
    int g_beat_scan_time;
    const char *g_server_address;
};

extern struct Config *const config;

#endif // !SETTINGS_H
