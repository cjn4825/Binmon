#include "../include/ring.h"
#include <stddef.h>

struct ring_buffer_t {
    // packets are not of fixed size so implement the client side reading here and use
    // that logic to send the data out...standard queue??
    char *offset;
    int max;
    size_t size;
};
