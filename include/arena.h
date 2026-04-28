#ifndef ARENA_H
#define ARENA_H

#include <unistd.h>

#define INIT_ARENA_SIZE 50000 // 50MB in bytes

// notes:
// beat thread: 1 page    malloc
// health thread: 4 page  malloc???
// proc: 2 pages          mmap
// bin: 2 pages           mmap
// ring buffer: 1 to 4 mb mmap

// use malloc for beat, health and other small ones...mmap for large ones like
// bin and ring buffer

struct Arena {
  size_t offset;
  size_t capacity;
  void *pool;
};

// notes:
//
// have one for each thread
// first need to figure out architecture
// only deallocate by deleting the whole thing
// after each run?

struct Arena *create_arena(void);
void *alloc_arena(struct Arena *arena, size_t size);
void reset_arena(struct Arena *arena);

#endif // !ARENA_H
