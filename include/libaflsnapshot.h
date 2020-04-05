#ifndef LIB_AFL_SNAPSHOT_H
#define LIB_AFL_SNAPSHOT_H

#include <stdlib.h>

int afl_snapshot_init();

int afl_snapshot_start(void *(cleanup)(void), void *shm_addr, size_t shm_size);

int afl_snapshot_end(void);

#endif

