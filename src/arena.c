#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "../include/arena.h"
#include "../include/settings.h"
#include "../include/logging.h"

struct Arena* create_arena(void){

    void *p = mmap(
        NULL,
        INIT_ARENA_SIZE,
        PROT_READ | PROT_WRITE,
        NULL,       // this whole thing is wrong research later
        -1,
        0
    );

    if(unlikely(p == NULL)){
        LOG("could not mmap Arena pool");
        exit(EXIT_FAILURE);
    }

    struct Arena *a = mmap(
        NULL,
        sizeof(struct Arena),
        PROT_READ | PROT_WRITE,
        NULL,       // this whole thing is wrong research later
        -1,
        0
    );

    if(unlikely(a == NULL)){
        LOG("could not mmap Arena");
        exit(EXIT_FAILURE);
    }

    a->pool = p;
    a->capacity = INIT_ARENA_SIZE;

    return a;
}

void* alloc_arena(struct Arena *arena, size_t size){
    if((arena->offset + size) >= arena->capacity){
        LOG("Arena reached capacity...");
        exit(EXIT_FAILURE);
    }

    size_t original_place = arena->offset;

    arena->offset += size; // not sure in right units...
    return &arena->pool[original_place];
}

void reset_arena(struct Arena * arena){
    free(arena);
}
