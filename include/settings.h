#ifndef SETTINGS_H
#define SETTINGS_H

// integrate into yaml file configuration

#define MAGIC_NUMBER 0xDEEBB1F         // magic number so client knows
#define VERSION 1.0                    // program version

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

// #define LOG_VALUE settings[0]
// #define PORT settings[1]
// #define SERVER_ADDRESS settings[2]
// #define DELTA_PROGRAM settings[3]
// #define RESIZE_PERCENTAGE settings[4]
// #define DEFAULT_OLD settings[5]
// #define DEFAULT_MAX settings[6]
// #define STATS_LENGTH settings[7]
// #define BIN_SCAN_TIME settings[8]
// #define HEALTH_SCAN_TIME settings[9]
// #define BEAT_SCAN_TIME settings[10]

// #define SETTINGS_COUNT 11             // number of settings

#define PROC 1
#define BIN 2
#define BEAT 3

// extern int settings[];
extern int g_port;
extern int g_delta_program;
extern int g_resize_percentage;
extern int g_proc_pool_size;
extern int g_default_old;
extern int g_default_max;
extern int g_stats_length;
extern int g_bin_scan_time;
extern int g_health_scan_time;
extern int g_beat_scan_time;
extern const char *g_server_address;

#endif // !SETTINGS_H
