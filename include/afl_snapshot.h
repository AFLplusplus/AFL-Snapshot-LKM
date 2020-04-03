#ifndef AFL_SNAPSHOT_H
#define AFL_SNAPSHOT_H

#include <linux/limits.h>

#define AFL_SNAPSHOT_FILE_NAME "/dev/afl_snapshot"

#define AFL_SNAPSHOT_IOCTL_MAGIC 44313

struct afl_snapshot_start_args {

  unsigned long cleanup_rtn;
  unsigned long shm_addr;
  unsigned long shm_size;

};

#define AFL_SNAPSHOT_IOCTL_START _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 1, struct afl_snapshot_start_args*)
#define AFL_SNAPSHOT_IOCTL_END _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 2)
#define AFL_SNAPSHOT_IOCTL_CLEAN _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 3)

#endif
