#ifndef SETTINGS_H
#define SETTINGS_H

struct config_t {
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
    char g_server_address[12];
};

extern struct config_t *g_config;

#endif // !SETTINGS_H
