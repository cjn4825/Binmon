#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <yaml.h>

#include "../include/proctypes.h"
#include "../include/logging.h"
#include "../include/settings.h"

// int settings[SETTINGS_COUNT] = {0};

struct Config *const config;

void get_log_time(char *buffer, size_t length){
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, length, "%H:%M:%S", t);
}

// void clean(struct thread_context_t *const context, int type){

//     if(type == PROC){
//         free(context->p_proc_info->data);
//         free(context->p_proc_info);
//         context->p_proc_info->total_tlv_size = 0;
//         context->p_proc_info->total_ph_size = 0;
//     }
//     else if (type == BIN){
//         free(context->p_bin_info->data);
//         free(context->p_bin_info);
//         context->p_bin_info->total_tlv_size = 0;
//         context->p_bin_info->total_ph_size = 0;
//     }
//     else {
//         LOG("Passed wrong type into clean");
//         exit(EXIT_FAILURE);
//     }
// }

// void check_capacity(struct proc_info_t *const p_info){
//     if(p_info->proc_count >= p_info->capacity * g_resize_percentage){
//         size_t new_cap = p_info->capacity *= 2;

//         p_info->data = realloc(p_info->data, new_cap);

//         if(unlikely(p_info->data == NULL)){
//             LOG("Data failed to resize from realloc");
//             exit(EXIT_FAILURE);
//         }

//         p_info->capacity = new_cap;

//     }
// }

void import_settings(const char *const path){
    FILE *p_file = fopen(path, "r");
    yaml_parser_t parser;
    yaml_event_t event;

    if(unlikely(!yaml_parser_initialize(&parser))){
        LOG("could not init yaml parser...");
        exit(EXIT_FAILURE);
    }

    if(unlikely(p_file == NULL)){
        LOG("could not open yaml settings file...");
        exit(EXIT_FAILURE);
    }

    yaml_parser_set_input_file(&parser, p_file);

    int i = 0;
    while(1){
        if(!yaml_parser_parse(&parser, &event)){
            break;
        }

        if(event.type == YAML_SCALAR_EVENT){

            yaml_char_t *value = event.data.scalar.value;
            //
            //change so it goes by key value not position to
            //set variables
            switch (i) {
                case 0:
                    g_log_value = *value; // change to be part of config?
                    break;
                case 1:
                    config->g_port = *value;
                    break;
                case 2:
                    config->g_server_address = (const char*)value;
                    break;
                case 3:
                    config->g_proc_pool_size = *value;
                    break;
                case 4:
                    config->g_delta_program = *value;
                    break;
                case 5:
                    config->g_resize_percentage = *value / 100;
                    break;
                case 6:
                    config->g_default_old = *value;
                    break;
                case 7:
                    config->g_default_max = *value;
                    break;
                case 8:
                    config->g_stats_length = *value;
                    break;
                case 9:
                    config->g_bin_scan_time = *value;
                    break;
                case 10:
                    config->g_health_scan_time = *value;
                    break;
                case 11:
                    config->g_beat_scan_time = *value;
                    break;
            }
        }

        if(event.type == YAML_STREAM_END_EVENT){
            break;
        }

        i++;
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(p_file);
}
