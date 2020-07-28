#ifndef AFL_SNAPSHOT_H
#define AFL_SNAPSHOT_H

#include <linux/ioctl.h>

#define AFL_SNAPSHOT_FILE_NAME "/dev/afl_snapshot"

#define AFL_SNAPSHOT_IOCTL_MAGIC 44313

#define AFL_SNAPSHOT_EXCLUDE_VMRANGE _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 1, struct afl_snapshot_vmrange_args*)
#define AFL_SNAPSHOT_INCLUDE_VMRANGE _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 2, struct afl_snapshot_vmrange_args*)
#define AFL_SNAPSHOT_IOCTL_TAKE      _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 3, int)
#define AFL_SNAPSHOT_IOCTL_RESTORE   _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 4)
#define AFL_SNAPSHOT_IOCTL_CLEAN     _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 5)

#define AFL_SNAPSHOT_MMAP  1
#define AFL_SNAPSHOT_BLOCK 2
#define AFL_SNAPSHOT_COW   4
#define AFL_SNAPSHOT_FDS   8
#define AFL_SNAPSHOT_EXIT  16

struct afl_snapshot_vmrange_args {

  unsigned long start, end;

};

#endif

