#ifndef SEND_H
#define SEND_H

#include <stddef.h>
#include <stdint.h>

struct send_queue {
    uint8_t *pool;
    _Atomic size_t head;
    _Atomic size_t tail;
};

struct send_queue* send_init();
// void send_init(struct send_queue* q);
int send_push(struct send_queue* q, void* data);
int send_pop(struct send_queue *q, void** out_data);

#endif // !SEND_H
