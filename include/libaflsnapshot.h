#ifndef LIB_AFL_SNAPSHOT_H
#define LIB_AFL_SNAPSHOT_H

#include "afl_snapshot.h"

int  afl_snapshot_init();
void afl_snapshot_exclude_vmrange(void *start, void *end);
void afl_snapshot_include_vmrange(void *start, void *end);
int  afl_snapshot_do(void);
int  afl_snapshot_take(int config);
void afl_snapshot_restore(void);
void afl_snapshot_clean(void);

#endif

