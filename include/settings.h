#ifndef SETTINGS_H
#define SETTINGS_H

// integrate into yaml file configuration

#define MAGIC_NUMBER 0xDEEBB1F      // magic number so client knows
#define PORT 9000                   // port where client is listening on
#define SERVER_ADDRESS "127.0.0.1"  // server address (this is the server)

#define VERSION 1.0             // program version
#define DELTA_PROGRAM 1         // tick rate of the program
#define RESIZE_PERCENTAGE .90   // What percent full until resizing
#define DEFAULT_OLD 2592000     // how many days in seconds until a process is old(30 days)
#define DEFAULT_MAX 1024        // default size of max procs before relloc
#define STATS_LENGTH 256        // lenght of stats of each process
#define BIN_SCAN_TIME 60        // amount of time in seconds that the bin scan happens

#define LOG_VALUE 1             // turn logging on

#endif // !SETTINGS_H
