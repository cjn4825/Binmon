#ifndef ARENA_H
#define ARENA_H

#include <cstddef>

typedef struct {
    size_t offset;
    size_t capacity;
    char *buffer;
} Arena;

//notes:
//
//uses mmap to create buffer of size 50 mb or so
//have one for each thread
//first need to figure out architecture
//only deallocate by deleting the whole thing





// void reset_arena(void *p);
// Arena init_arena(size_t size);

#endif // !ARENA_H
