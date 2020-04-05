#include "libaflsnapshot.h"

#include <sys/ioctl.h>
#include "afl_snapshot.h"

static int dev_fd;

int afl_snapshot_init() {

  dev_fd = open(AFL_SNAPSHOT_FILE_NAME, 0);
  return dev_fd;

}

int afl_snapshot_start(void *(cleanup)(void), void *shm_addr, size_t shm_size) {

  struct afl_snapshot_start_args args;
  args.cleanup_rtn = (unsigned long)cleanup;
  args.shm_addr = (unsigned long)shm_addr;
  args.shm_size = (unsigned long)shm_size;

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_START, &args);

}

int afl_snapshot_end(void) {

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_END);

}

