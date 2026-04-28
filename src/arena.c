#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../include/arena.h"
#include "../include/logging.h"

static inline int mmap_size(){
    return INIT_ARENA_SIZE - (INIT_ARENA_SIZE % getpagesize()) + getpagesize();
}

struct Arena* create_arena(void){

    char* p = malloc(sizeof(struct Arena));

    if(unlikely(p == NULL)){
        LOG("could not mmap Arena pool");
        exit(EXIT_FAILURE);
    }
    struct Arena *a = mmap(
        NULL,
        mmap_size(),
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,       // this whole thing is wrong research later
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

// reset should just move the pointer to the start? then zeroize the data?
// so i need to create another function that fully destroys it like this one
//
void reset_arena(struct Arena *arena){
    munmap(arena->pool, sizeof(arena->pool));
    free(arena);
}
