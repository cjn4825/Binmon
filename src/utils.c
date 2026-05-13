#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <yaml.h>

#include "../include/logging.h"
#include "../include/settings.h"

void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}

void import_settings(const char *const path){
    FILE *p_file = fopen(path, "r");
    yaml_parser_t parser;
    yaml_token_t token;

    char *last_key = NULL;
    int state = STATE_NONE;
    int done;

    g_config = calloc(1, sizeof(struct config_t));

    CHECK_ERROR(unlikely(!yaml_parser_initialize(&parser)), "could not init yaml parser");
    CHECK_ERROR(unlikely(g_config == NULL), "could not allocate g_config struct");
    CHECK_ERROR(unlikely(p_file == NULL), "could not open yaml settings file");

    yaml_parser_set_input_file(&parser, p_file);

    while(!done){
        if(!yaml_parser_scan(&parser, &token)) break;

        switch (token.type){
            case YAML_KEY_TOKEN:
                state = STATE_KEY;
                break;
            case YAML_VALUE_TOKEN:
                state = STATE_VALUE;
                break;
            case YAML_SCALAR_TOKEN: {
                char *value = (char *)token.data.scalar.value;

                if(state == STATE_KEY){
                    if(last_key) free(last_key);
                    last_key = strdup(value);
                }
                else if(state == STATE_VALUE && last_key){
                    if(strcmp(last_key, "port") == 0){
                        g_config->g_port = atoi(value);
                    }
                    else if(strcmp(last_key, "delta_program") == 0){
                        g_config->g_delta_program = atoi(value);
                    }
                    else if(strcmp(last_key, "resize_percentage") == 0){
                        g_config->g_resize_percentage = atoi(value);
                    }
                    else if(strcmp(last_key, "proc_pool_size") == 0){
                        g_config->g_proc_pool_size = atoi(value);
                    }
                    else if(strcmp(last_key, "bin_pool_size") == 0){
                        g_config->g_bin_pool_size = atoi(value);
                    }
                    else if(strcmp(last_key, "send_pool_size") == 0){
                        g_config->g_send_pool_size = atoi(value);
                    }
                    else if(strcmp(last_key, "default_old") == 0){
                        // input in days output in seconds
                        g_config->g_default_old = 86400 * atoi(value);
                    }
                    else if(strcmp(last_key, "default_max") == 0){
                        g_config->g_default_max = atoi(value);
                    }
                    else if(strcmp(last_key, "stats_length") == 0){
                        g_config->g_stats_length = atoi(value);
                    }
                    else if(strcmp(last_key, "bin_scan_time") == 0){
                        g_config->g_bin_scan_time = atoi(value);
                    }
                    else if(strcmp(last_key, "health_scan_time") == 0){
                        g_config->g_health_scan_time = atoi(value);
                    }
                    else if(strcmp(last_key, "beat_scan_time") == 0){
                        g_config->g_beat_scan_time = atoi(value);
                    }
                    else if(strcmp(last_key, "server_address") == 0){
                        if(strlen(value) > 12){
                            value = "127.0.0.1";
                        }
                        memcpy(g_config->g_server_address, value, strlen(value));
                    }
                }

                break;
            }

            case YAML_STREAM_END_TOKEN:
                done = 1;
                break;

            default: break;
        }

        yaml_token_delete(&token);
        if(last_key) free(last_key);
        yaml_parser_delete(&parser);
        fclose(p_file);
    }
}
