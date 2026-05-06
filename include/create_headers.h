#ifndef HEADERS_H
#define HEADERS_H

void create_headers(void *offset);
// void* create_headers(void *area);
// void* binmon_header(void *header_loc);
struct packet_header* binmon_header(void *header_loc);

#define BINARY_TYPE 0
#define PROC_TYPE 1


#endif // !HEADERS_H
