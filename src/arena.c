#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "../include/arena.h"
#include "../include/logging.h"

struct Arena* create_arena(void){

    uint8_t* p = malloc(sizeof(struct Arena));

    CHECK_ERROR(unlikely(p == NULL), "could not mmap Arena pool");

    size_t mmap_size = INIT_ARENA_SIZE - (INIT_ARENA_SIZE % getpagesize()) + getpagesize();

    struct Arena *a = mmap(
        NULL,
        mmap_size,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0
    );

    CHECK_ERROR(unlikely(a == NULL), "could not mmap Arena");

    a->pool = p;
    a->capacity = INIT_ARENA_SIZE;

    return a;
}

void* alloc_arena(struct Arena *arena, size_t size){

    assert(arena->capacity > 0);

    CHECK_ERROR(
        (arena->offset + size) >= arena->capacity,
        "Arena reached capacity"
    );

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
