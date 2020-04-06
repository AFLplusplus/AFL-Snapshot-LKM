#ifndef LIB_AFL_SNAPSHOT_H
#define LIB_AFL_SNAPSHOT_H

#include <stdlib.h>

int afl_snapshot_init();

int afl_snapshot_do(void);
int afl_snapshot_clean(void);

#endif

