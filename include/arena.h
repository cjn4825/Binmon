#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>

// REPLACE THIS WITH sizeof???
#define INIT_ARENA_SIZE 50000

struct Arena {
    size_t offset;
    size_t capacity;
    void   *pool;
};

//notes:
//
//have one for each thread
//first need to figure out architecture
//only deallocate by deleting the whole thing
//after each run?





struct Arena* create_arena(void);
void* alloc_arena(struct Arena *arena, size_t size);
void reset_arena(struct Arena * arena);

#endif // !ARENA_H
